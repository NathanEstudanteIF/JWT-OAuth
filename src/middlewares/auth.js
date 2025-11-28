import jsonwebtoken from "jsonwebtoken";
import dotenv from "dotenv";

dotenv.config();

export const JWT_SECRET = process.env.JWT_SECRET;

export function tokenValidated(req, res, next) {
  const authHeader = req.headers.authorization;
  const token = authHeader && authHeader.split(" ")[1];

  if (!token) {
    return res.status(401).send("Acesso negado. Nenhum token fornecido.");
  }

  try {
    const payload = jsonwebtoken.verify(token, JWT_SECRET);
    req.headers.user = payload.user;
    return next();
  } catch (error) {
    console.log(error);
    return res.status(401).json({ message: "Token inválido" });
  }
}

export function isAdmin(req, res, next) {
  const userHeader = req.headers.user;
  if (!userHeader) {
    return res.status(401).json({ message: "Usuário não autenticado" });
  }

  try {
    const user = JSON.parse(userHeader);
    if (user.role !== "admin") {
      return res.status(403).json({ message: "Acesso negado. Requer privilégios de administrador." });
    }
    next();
  } catch (error) {
    return res.status(400).json({ message: "Erro ao validar permissões" });
  }
}
