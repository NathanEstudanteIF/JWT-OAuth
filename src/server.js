import express from "express";
import cors from "cors";
import dotenv from "dotenv";
import bcrypt from "bcryptjs";
import sequelize from "./config/database.js";
import User from "./models/user.js";
import authRoutes from "./routes/authRoutes.js";
import privateRoutes from "./routes/privateRoutes.js";

dotenv.config();

const app = express();
app.use(cors());
app.use(express.json());

// Rotas
app.get("/", (_, res) => res.status(200).json({ message: "API disponível" }));
app.use("/auth", authRoutes);
app.use(privateRoutes);

// Inicialização do Banco e Servidor
(async () => {
  try {
    await sequelize.authenticate();
    await sequelize.sync();
    console.log("Banco sincronizado com sucesso.");

    // Seed de usuário Admin
    const adminExists = await User.findOne({ where: { email: "admin@example.com" } });
    if (!adminExists) {
      const hashedPassword = await bcrypt.hash("admin123", 10);
      await User.create({
        name: "Admin User",
        email: "admin@example.com",
        password: hashedPassword,
        role: "admin",
      });
      console.log("Usuário admin criado com sucesso (admin@example.com / admin123).");
    }
  } catch (error) {
    console.error("Erro ao conectar ao banco:", error);
  }
})();

const PORT = process.env.PORT || 5000;

app.listen(PORT, () => {
  console.log(`Servidor rodando na porta ${PORT}`);
});
