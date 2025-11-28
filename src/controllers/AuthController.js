import bcrypt from "bcryptjs";
import jwt from "jsonwebtoken";
import axios from "axios";
import qs from "query-string";
import User from "../models/user.js";
import { v4 as uuidv4 } from "uuid"
import { JWT_SECRET } from "../middlewares/auth.js";
import RefreshToken from "../models/refreshToken.js";

async function createRefreshToken(user) {
  const expiredAt = new Date();
  expiredAt.setSeconds(expiredAt.getSeconds() + 86400);
  const token = uuidv4();

  const refreshToken = await RefreshToken.create({
    token: token,
    userId: user.id,
    expiresAt: expiredAt.getTime(),
  });

  return refreshToken.token;
}

async function exchangeCodeForAccessToken(code) {
  const GITHUB_ACCESS_TOKEN_URL = "https://github.com/login/oauth/access_token";
  const params = {
    code,
    grant_type: "authorization_code",
    redirect_uri: process.env.REDIRECT_URI,
    client_id: process.env.CLIENT_ID,
    client_secret: process.env.CLIENT_SECRET,
  };

  const { data } = await axios.post(GITHUB_ACCESS_TOKEN_URL, params, {
    headers: {
      "Content-Type": "application/json",
      Accept: "application/json",
    },
  });

  if (typeof data === "object" && data.access_token) {
    return data.access_token;
  }

  return qs.parse(data).access_token;
}

async function fetchUser(token) {
  const response = await axios.get("https://api.github.com/user", {
    headers: { Authorization: `Bearer ${token}` },
  });

  const user = response.data;

  if (!user.email) {
    const emailsResponse = await axios.get("https://api.github.com/user/emails", {
      headers: { Authorization: `Bearer ${token}` },
    });
    const primaryEmail = emailsResponse.data.find((email) => email.primary && email.verified);
    if (primaryEmail) {
      user.email = primaryEmail.email;
    }
  }

  return user;
}

async function persistUser(payload) {
  const [user] = await User.findOrCreate({
    where: { githubId: payload.githubId },
    defaults: {
      githubId: payload.githubId,
      name: payload.name,
      login: payload.login,
      profileUrl: payload.profileUrl,
      email: payload.email,
    },
  });
  return user;
}

export default {
  async register(req, res) {
    try {
      const { name, email, password, role } = req.body;

      if (!name || !email || !password) {
        return res.status(400).json({ message: "Dados incompletos" });
      }

      const userExists = await User.findOne({ where: { email } });
      if (userExists) {
        return res.status(400).json({ message: "E-mail já cadastrado" });
      }

      const hashedPassword = await bcrypt.hash(password, 10);

      const user = await User.create({
        name,
        email,
        password: hashedPassword,
        role: role || "user",
      });

      return res.status(201).json({
        id: user.id,
        name: user.name,
        email: user.email,
        role: user.role,
      });
    } catch (error) {
      return res.status(500).json({ message: "Erro ao registrar usuário", error });
    }
  },

  async login(req, res) {
    try {
      const { email, password } = req.body;

      if (!email || !password) {
        return res.status(400).json({ message: "E-mail e senha são obrigatórios" });
      }

      const user = await User.findOne({ where: { email } });
      if (!user || !user.password) {
        return res.status(401).json({ message: "Credenciais inválidas" });
      }

      const isPasswordValid = await bcrypt.compare(password, user.password);
      if (!isPasswordValid) {
        return res.status(401).json({ message: "Credenciais inválidas" });
      }

      const payload = {
        id: user.id,
        name: user.name,
        email: user.email,
        role: user.role,
      };

      const token = jwt.sign({ user: JSON.stringify(payload) }, JWT_SECRET, {
        expiresIn: "20s",
      });

      const refreshToken = await createRefreshToken(user);

      return res.status(200).json({
        data: {
          user: payload,
          token,
          refreshToken
        }
      });
    } catch (error) {
      return res.status(500).json({ message: "Erro no login", error });
    }
  },

  githubLogin(_, res) {
    const GITHUB_AUTH_URL = "https://github.com/login/oauth/authorize";
    const params = {
      response_type: "code",
      scope: "user",
      client_id: process.env.CLIENT_ID,
      redirect_uri: process.env.REDIRECT_URI,
    };

    res.redirect(`${GITHUB_AUTH_URL}?${qs.stringify(params)}`);
  },

  async githubCallback(req, res) {
    try {
      const { code } = req.query;
      if (!code) {
        return res.status(401).json({ mensagem: "Código ausente" });
      }

      const accessToken = await exchangeCodeForAccessToken(code);
      const githubData = await fetchUser(accessToken);

      const userPayload = {
        githubId: String(githubData.id),
        name: githubData.name || githubData.login,
        login: githubData.login,
        profileUrl: githubData.avatar_url,
        email: githubData.email,
      };

      const user = await persistUser(userPayload);

      const tokenPayload = {
        id: user.id,
        name: user.name,
        email: user.email,
        role: user.role,
      };

      const jwtToken = jwt.sign({ user: JSON.stringify(tokenPayload) }, JWT_SECRET, {
        expiresIn: "24h",
      });

      const refreshToken = await createRefreshToken(user);

      return res.status(200).json({
        data: {
          user: tokenPayload,
          jwtToken,
          refreshToken
        }
      });
    } catch (err) {
      console.log("err", err.response?.data || err.message);
      res
        .status(500)
        .json({ mensagem: "Erro ao processar autenticação", erro: err.message });
    }
  },

  async refreshToken(req, res) {
    const { requestToken } = req.body;
    if (!requestToken) {
      return res.status(403).json({ message: "Refresh Token é necessário!" });
    }
    try {
      const refreshToken = await RefreshToken.findOne({ where: { token: requestToken } });

      if (!refreshToken) {
        return res.status(403).json({ message: "Refresh token não está no banco de dados!" });
      }

      if (RefreshToken.verifyExpiration(refreshToken)) {
        RefreshToken.destroy({ where: { id: refreshToken.id } });
        return res.status(403).json({
          message: "Refresh token expirou. Por favor, faça login novamente.",
        });
      }

      const user = await User.findByPk(refreshToken.userId);

      const payload = {
        id: user.id,
        name: user.name,
        email: user.email,
        role: user.role,
      };

      const newAccessToken = jwt.sign({ user: JSON.stringify(payload) }, JWT_SECRET, { expiresIn: "20s" });

      return res.status(200).json({
        accessToken: newAccessToken,
        refreshToken: refreshToken.token,
      });
    } catch (err) {
      return res.status(500).send({ message: err });
    }
  },

  async logout(req, res) {
    try {
      const { requestToken } = req.body;
      if (!requestToken) {
        return res.status(400).json({ message: "Refresh Token é necessário para logout!" });
      }
      await RefreshToken.destroy({ where: { token: requestToken } });
      return res.status(200).json({ message: "Logout realizado com sucesso!"
    });
    } catch (err) {
      return res.status(500).send({ message: err });
    }
  },
};