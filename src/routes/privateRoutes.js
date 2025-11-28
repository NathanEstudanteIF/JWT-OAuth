import { Router } from "express";
import { tokenValidated, isAdmin } from "../middlewares/auth.js";

const router = Router();

router.use(tokenValidated);

router.get("/private", (req, res) => {
  const currentUser = JSON.parse(req.headers.user || "{}");
  return res.status(200).json({
    message: "Rota privada acessada",
    data: { userLogged: currentUser },
  });
});

router.get("/admin", isAdmin, (req, res) => {
  return res.status(200).json({
    message: "Rota de administrador acessada com sucesso!",
  });
});

export default router;
