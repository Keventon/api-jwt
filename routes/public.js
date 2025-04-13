import express from "express";
import { PrismaClient } from "@prisma/client";
import bcrypt from "bcrypt";
import jwt from "jsonwebtoken";

const prisma = new PrismaClient();
const router = express.Router();

const JWT_SECRET = process.env.JWT_SECRET;

router.post("/cadastro", async (req, res) => {
  try {
    const user = req.body;

    const salt = await bcrypt.genSalt(10);
    const hashPassword = await bcrypt.hash(user.password, salt);

    const response = await prisma.user.create({
      data: {
        name: user.name,
        email: user.email,
        password: hashPassword,
      },
    });

    res.status(201).json(response);
  } catch (error) {
    res.status(500).json({ message: "Erro no servidor. Tente novamente" });
  }
});

router.post("/login", async (req, res) => {
  try {
    const user = req.body;

    const userDb = await prisma.user.findUnique({
      where: { email: user.email },
    });

    if (!userDb) {
      return res.status(404).json({ message: "Usuário não encontrado" });
    }

    const isMatch = await bcrypt.compare(user.password, userDb.password);

    if (!isMatch) {
      return res.status(400).json({ message: "Senha inválida" });
    }

    //Gerar JWT
    const token = jwt.sign({ id: userDb.id }, JWT_SECRET, { expiresIn: "1m" });

    res.status(200).json(token);
  } catch (error) {
    res.status(500).json({ message: "Erro no servidor. Tente novamente" });
  }
});

export default router;
