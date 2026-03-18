console.log("🔥 BACKEND NOVO ATIVO 🔥")

require("dotenv").config();

if (!process.env.JWT_SECRET) {
  throw new Error("JWT_SECRET não definido no ambiente");
}
const express = require("express");
const axios = require("axios");
const cors = require("cors");
const { Pool } = require("pg");
const { MercadoPagoConfig, Preference, Payment } = require("mercadopago");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const rateLimit = require("express-rate-limit");

const app = express();
app.set("trust proxy", 1);

const nodemailer = require("nodemailer");

const transporter = nodemailer.createTransport({
  service: "gmail",
  auth: {
    user: process.env.EMAIL_USER,
    pass: process.env.EMAIL_PASS
  }
});

app.use(cors());

/* =============================
   BLOQUEIO DE BOTS
============================= */

app.use((req, res, next) => {

  const ua = req.headers["user-agent"] || "";

  const bots = [
    "curl",
    "wget",
    "python",
    "scrapy"
  ];

  const blocked = bots.some(bot =>
    ua.toLowerCase().includes(bot)
  );

  if (blocked) {
    return res.status(403).json({
      erro: "Acesso não permitido"
    });
  }

  next();

});

/* =============================
   PROTEÇÃO GLOBAL ANTI FLOOD
============================= */

const globalLimiter = rateLimit({
  windowMs: 60 * 1000,
  max: 100,
  standardHeaders: true,
  legacyHeaders: false,
  message: {
    erro: "Muitas requisições. Aguarde alguns segundos."
  }
});

app.use(globalLimiter);


app.use((req, res, next) => {

  // Libera tudo temporariamente
  next()

});

app.use(express.json({ limit: "1mb" }));

/* =============================
   MIDDLEWARE AUTENTICAÇÃO
============================= */

function autenticar(req, res, next) {

  const authHeader = req.headers.authorization;

  if (!authHeader) {
    return res.status(401).json({ erro: "Token não fornecido" });
  }

  const token = authHeader.split(" ")[1];

  try {

    const decoded = jwt.verify(
      token,
      process.env.JWT_SECRET
    );

    req.usuario = decoded;

    next();

  } catch (err) {

    return res.status(401).json({ erro: "Token inválido" });

  }

}

function verificarAdmin(req, res, next) {

  if (!req.usuario || !req.usuario.is_admin) {

    return res.status(403).json({
      erro: "Acesso permitido apenas para administradores"
    });

  }

  next();

}

const loginLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutos
  max: 20,
  message: { erro: "Muitas tentativas. Tente novamente em 15 minutos." }
});

const consultaLimiter = rateLimit({
  windowMs: 1 * 60 * 1000, // 1 minuto
  max: 10,
  message: { erro: "Muitas consultas. Aguarde 1 minuto." }
});

/* =============================
   ANTI ABUSO POR USUÁRIO
============================= */

const consultasUsuario = {};

function antiAbusoConsulta(req, res, next) {

  const userId = req.usuario.id;

  if (!userId) return next();

  const agora = Date.now();

  if (!consultasUsuario[userId]) {
    consultasUsuario[userId] = [];
  }

  consultasUsuario[userId] = consultasUsuario[userId]
    .filter(t => agora - t < 60000);

  if (consultasUsuario[userId].length >= 5) {

    return res.status(429).json({
      erro: "Muitas consultas. Aguarde 1 minuto."
    });

  }

  consultasUsuario[userId].push(agora);

  next();

}

/* =============================
   MERCADO PAGO CONFIG
============================= */

const client = new MercadoPagoConfig({
  accessToken: process.env.MP_ACCESS_TOKEN
});

/* =============================
   BANCO POSTGRES
============================= */

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: { rejectUnauthorized: false }
});

/* =============================
   TESTE BANCO
============================= */

app.get("/api/test-db", async (req, res) => {
  try {
    const result = await pool.query("SELECT NOW()");
    res.json(result.rows);
  } catch (error) {
    res.status(500).json({ erro: error.message });
  }
});

/* =============================
   CADASTRO
============================= */

app.post("/api/cadastro", async (req, res) => {
  const { nome, sobrenome, telefone, email, senha, confirmarSenha } = req.body;

  if (!nome || !sobrenome || !telefone || !email || !senha || !confirmarSenha)
    return res.status(400).json({ erro: "Preencha todos os campos" });

  if (senha !== confirmarSenha)
    return res.status(400).json({ erro: "As senhas não coincidem" });

  try {
    const usuarioExistente = await pool.query(
      "SELECT * FROM usuarios WHERE email = $1",
      [email]
    );

    if (usuarioExistente.rows.length > 0)
      return res.status(400).json({ erro: "Email já cadastrado" });

    const senhaHash = await bcrypt.hash(senha, 10);

    const novoUsuario = await pool.query(
      `INSERT INTO usuarios 
       (nome, sobrenome, telefone, email, senha, saldo)
       VALUES ($1,$2,$3,$4,$5,$6)
       RETURNING id, nome, sobrenome, email, saldo, is_admin`,
      [nome, sobrenome, telefone, email, senhaHash, 3]
    );

    const usuario = novoUsuario.rows[0];

    const token = jwt.sign(
      { id: usuario.id, is_admin: usuario.is_admin },
      process.env.JWT_SECRET,
      { expiresIn: "1d" }
    );

    res.json({ token, usuario });

    const link = `https://engemafer.com.br/verificar-email.html?token=${token}`;

    setImmediate(async () => {
      try {
        await transporter.sendMail({
          from: `"Fipe Total" <${process.env.EMAIL_USER}>`,
          to: email,
          subject: "Verifique seu email",
          html: `<h2>Confirme sua conta</h2>
                 <p>Clique abaixo:</p>
                 <a href="${link}">Confirmar Email</a>`
        });
      } catch (err) {
        console.log("ERRO EMAIL:", err.message);
      }
    });

  } catch (error) {
    console.log("ERRO REAL CADASTRO:");
    console.log(error);
    console.log("DETAIL:", error.detail);
    console.log("CODE:", error.code);

    res.status(500).json({
      erro: error.message,
      detail: error.detail
    });
  }
});

app.get("/api/verificar-email", async (req, res) => {

  const { token } = req.query

  try {

    const decoded = jwt.verify(token, process.env.JWT_SECRET)

    await pool.query(
      "UPDATE usuarios SET email_verificado = TRUE WHERE id = $1",
      [decoded.id]
    )

    res.redirect("/login.html")

  } catch {

    res.send("Link inválido")

  }

})

/* =============================
   LOGIN
============================= */

app.post("/api/login", loginLimiter, async (req, res) => {
  const { email, senha } = req.body;

  try {

    const result = await pool.query(
      "SELECT * FROM usuarios WHERE email = $1",
      [email]
    );

    if (result.rows.length === 0) {
      return res.status(400).json({ erro: "Usuário não encontrado" });
    }

    const usuario = result.rows[0]; // 🔥 FALTAVA ISSO

    // 🔥 LIBERA LOGIN DIRETO (REMOVE BLOQUEIO)

    if (usuario.bloqueado) {
      return res.status(403).json({ erro: "Usuário bloqueado" });
    }

    const senhaValida = await bcrypt.compare(senha, usuario.senha);

    if (!senhaValida) {
      return res.status(400).json({ erro: "Senha incorreta" });
    }

    const token = jwt.sign(
      { id: usuario.id, is_admin: usuario.is_admin },
      process.env.JWT_SECRET,
      { expiresIn: "1d" }
    );

    res.json({
      token,
      usuario: {
        id: usuario.id,
        nome: usuario.nome,
        email: usuario.email,
        saldo: usuario.saldo,
        is_admin: usuario.is_admin
      }
    });

  } catch (err) {
    console.log(err); // 👉 importante pra debug
    res.status(500).json({ erro: "Erro no servidor" });
  }
});

/* =============================
   CRIAR PAGAMENTO
============================= */

app.post("/api/criar-pagamento", autenticar, async (req, res) => {

  try {

    const { valor } = req.body;
    const userId = req.usuario.id;

    if (!valor || !userId)
      return res.status(400).json({ erro: "Dados inválidos" });

    const preference = new Preference(client);

    const response = await preference.create({
      body: {
        items: [
          {
            title: "Recarga de Créditos - Fipe Total",
            quantity: 1,
            currency_id: "BRL",
            unit_price: Number(valor)
          }
        ],
        metadata: {
          userId: userId,
          valor: valor
        },
        notification_url: "https://fipe-total-backend.onrender.com/api/webhook-mercadopago",
        back_urls: {
          success: `https://engemafer.com.br/sucesso.html?valor=${valor}`,
          failure: "https://engemafer.com.br/erro.html",
          pending: "https://engemafer.com.br/pendente.html"
        },
        auto_return: "approved"
      }
    });

    res.json({ id: response.id });

  } catch (error) {
    console.log(error);
    res.status(500).json({ erro: "Erro ao criar pagamento" });
  }

});

/* =============================
   WEBHOOK MERCADO PAGO
============================= */

app.post("/api/webhook-mercadopago", async (req, res) => {

  console.log("===================================");
  console.log("Webhook chamado!");
  console.log("Body recebido:", req.body);
  console.log("===================================");

  try {

    const paymentClient = new Payment(client);

    let paymentId;

    // 🔥 SE VIER MERCHANT ORDER
    if (req.body.topic === "merchant_order") {

      const orderUrl = req.body.resource;

      const orderResponse = await axios.get(orderUrl, {
        headers: {
          Authorization: `Bearer ${process.env.MP_ACCESS_TOKEN}`
        }
      });

      const order = orderResponse.data;

      if (!order.payments || order.payments.length === 0) {
        console.log("Order sem pagamento ainda.");
        return res.sendStatus(200);
      }

      paymentId = order.payments[0].id;

      console.log("Payment ID vindo da order:", paymentId);

    } else {

      paymentId =
        req.body?.data?.id ||
        req.body?.id;

    }

    if (!paymentId) {
      console.log("Nenhum paymentId encontrado.");
      return res.sendStatus(200);
    }

    const payment = await paymentClient.get({ id: paymentId });

    console.log("Status do pagamento:", payment.status);

    if (payment.status !== "approved") {
      console.log("Pagamento ainda não aprovado.");
      return res.sendStatus(200);
    }

    const userId = payment.metadata?.userId || payment.metadata?.user_id;
    const valorPago = Number(payment.metadata?.valor);

    if (!userId || !valorPago) {
      console.log("Metadata inválida:", payment.metadata);
      return res.sendStatus(200);
    }

    const jaProcessado = await pool.query(
      "SELECT * FROM pagamentos WHERE payment_id = $1",
      [paymentId]
    );

    if (jaProcessado.rows.length > 0) {
      console.log("Pagamento já processado.");
      return res.sendStatus(200);
    }

    await pool.query(
      "UPDATE usuarios SET saldo = saldo + $1 WHERE id = $2",
      [valorPago, userId]
    );

    await pool.query(
      "INSERT INTO pagamentos (usuario_id, payment_id, valor) VALUES ($1,$2,$3)",
      [userId, paymentId, valorPago]
    );

    console.log("Saldo atualizado com sucesso!");

    res.sendStatus(200);

  } catch (error) {
    console.log("Erro geral no webhook:", error);
    res.sendStatus(200);
  }

});

/* =============================
   CONSULTA PROPRIETÁRIO (R$11,99)
============================= */

app.post("/api/proprietario-atual", autenticar, consultaLimiter, antiAbusoConsulta, async (req, res) => {

  try {

    const { placa } = req.body;
    const userId = req.usuario.id;
    const VALOR = 11.99;

    if (!placa || !userId) {
      return res.status(400).json({ erro: "Dados inválidos" });
    }

    const placaFormatada = placa
      .toUpperCase()
      .replace(/[^A-Z0-9]/g, "");

    /* =============================
       BUSCAR USUÁRIO
    ============================= */

    const usuario = await pool.query(
      "SELECT saldo, bloqueado FROM usuarios WHERE id = $1",
      [userId]
    );

    if (!usuario.rows.length) {
      return res.status(404).json({ erro: "Usuário não encontrado" });
    }

    const saldo = Number(usuario.rows[0].saldo);

    if (usuario.rows[0].bloqueado) {
      return res.status(403).json({ erro: "Conta bloqueada" });
    }

    if (saldo < VALOR) {
      return res.status(403).json({ erro: "Saldo insuficiente" });
    }

    /* =============================
       EVITA CONSULTA REPETIDA
    ============================= */

    const consultaRecente = await pool.query(
      `
      SELECT id FROM consultas
      WHERE usuario_id = $1
      AND placa = $2
      AND criado_em > NOW() - INTERVAL '5 minutes'
      `,
      [userId, placaFormatada]
    );

    if (consultaRecente.rows.length > 0) {

      return res.status(400).json({
        erro: "Essa placa já foi consultada recentemente."
      });

    }

    /* =============================
       CONSULTA API CHECKPRO
    ============================= */

    const response = await axios.post(
      "https://ws2.checkpro.com.br/servicejson.asmx/ConsultaProprietarioAtualPorPlaca",
      new URLSearchParams({
        cpfUsuario: process.env.CHECKPRO_CPF,
        senhaUsuario: process.env.CHECKPRO_SENHA,
        placa: placaFormatada
      }),
      {
        headers: {
          "Content-Type": "application/x-www-form-urlencoded"
        },
        timeout: 20000
      }
    );

    const data = response.data;

    console.log("CheckPro resposta:", data);

    if (!data || String(data.StatusRetorno) !== "1") {

      return res.status(400).json({
        erro: data?.MensagemRetorno || "Erro ao consultar veículo"
      });

    }

    /* =============================
       TRANSAÇÃO SEGURA
    ============================= */

    await pool.query("BEGIN");

    await pool.query(
      "UPDATE usuarios SET saldo = saldo - $1 WHERE id = $2",
      [VALOR, userId]
    );

    await pool.query(
      `
      INSERT INTO consultas 
      (usuario_id, placa, valor_pago, dados_json)
      VALUES ($1,$2,$3,$4)
      `,
      [userId, placaFormatada, VALOR, data]
    );

    await pool.query("COMMIT");

    /* =============================
       RESPOSTA FINAL
    ============================= */

    res.json({
      sucesso: true,
      dados: data,
      novoSaldo: saldo - VALOR
    });

  } catch (error) {

    try {
      await pool.query("ROLLBACK");
    } catch { }

    console.log("ERRO CONSULTA PROPRIETÁRIO:");
    console.log(error.response?.data || error.message);

    res.status(500).json({
      erro: "Erro interno do servidor"
    });

  }

});

/* =============================
   CONSULTA COMPLETA (R$54,90)
============================= */

app.post("/api/consulta-completa", autenticar, consultaLimiter, antiAbusoConsulta, async (req, res) => {

  try {

    const { placa } = req.body;
    const userId = req.usuario.id;
    const VALOR = Number(54.90);

    const usuario = await pool.query(
      "SELECT saldo, bloqueado FROM usuarios WHERE id = $1",
      [userId]
    );

    if (!usuario.rows.length)
      return res.status(404).json({ erro: "Usuário não encontrado" });



    const saldo = Number(usuario.rows[0].saldo);

    if (usuario.rows[0].bloqueado) {
      return res.status(403).json({ erro: "Conta bloqueada" });
    }

    if (saldo < VALOR)
      return res.status(403).json({ erro: "Saldo insuficiente" });

    const placaFormatada = placa.toUpperCase().replace(/[^A-Z0-9]/g, "");

    // 🔎 1. CACHE GLOBAL (QUALQUER USUÁRIO - 7 dias)
    const cacheGlobal = await pool.query(`
    SELECT * FROM consultas
    WHERE placa = $1
    AND criado_em > NOW() - INTERVAL '7 days'
    ORDER BY criado_em DESC
    LIMIT 1
`, [placaFormatada]);

    if (cacheGlobal.rows.length > 0) {

      console.log("⚡ CACHE GLOBAL USADO");

      return res.json({
        sucesso: true,
        dados: cacheGlobal.rows[0].dados_json,
        cache: true,
        novoSaldo: saldo // não cobra
      });
    }

    // 🔎 2. VERIFICAR SE O USUÁRIO JÁ CONSULTOU
    const consultaUsuario = await pool.query(`
    SELECT * FROM consultas
    WHERE usuario_id = $1
    AND placa = $2
    LIMIT 1
`, [userId, placaFormatada]);

    if (consultaUsuario.rows.length > 0) {

      console.log("♻️ CONSULTA REPETIDA");

      return res.json({
        sucesso: true,
        dados: consultaUsuario.rows[0].dados_json,
        repetida: true,
        novoSaldo: saldo // não cobra
      });
    }

    if (consultaRecente.rows.length > 0) {

      return res.status(400).json({
        erro: "Essa placa já foi consultada recentemente."
      })

    }

    const response = await axios.post(
      "https://ws2.checkpro.com.br/servicejson.asmx/ConsultaPacoteCompletoPorPlaca",
      new URLSearchParams({
        cpfUsuario: process.env.CHECKPRO_CPF,
        senhaUsuario: process.env.CHECKPRO_SENHA,
        placa: placaFormatada
      }),
      { headers: { "Content-Type": "application/x-www-form-urlencoded" } }
    );

    const data = response.data;

    console.log("Resposta CheckPro COMPLETA:", data);

    if (String(data.StatusRetorno) !== "1")
      return res.json({ erro: data.MensagemRetorno });

    // 🔒 Transação segura
    await pool.query("BEGIN");

    await pool.query(
      "UPDATE usuarios SET saldo = saldo - $1 WHERE id = $2",
      [VALOR, userId]
    );

    await pool.query(
      "INSERT INTO consultas (usuario_id, placa, valor_pago, dados_json) VALUES ($1,$2,$3,$4)",
      [userId, placaFormatada, VALOR, data]
    );

    await pool.query("COMMIT");

    res.json({
      sucesso: true,
      dados: data,
      novoSaldo: saldo - VALOR
    });

  } catch (error) {

    try {
      await pool.query("ROLLBACK");
    } catch { }

    res.status(500).json({ erro: "Erro interno do servidor" });

  }

});

/* =============================
   CONSULTA FIPE (GRÁTIS)
============================= */

app.get("/api/placafipe/:placa/:usuario_id?", autenticar, consultaLimiter, async (req, res) => {

  try {

    const { placa, usuario_id } = req.params;

    const placaFormatada = placa
      .toUpperCase()
      .replace(/[^A-Z0-9]/g, "");

    const response = await axios.post(
      "https://api.placafipe.com.br/getplacafipe",
      {
        placa: placaFormatada,
        token: process.env.FIPE_API_TOKEN
      },
      {
        headers: { "Content-Type": "application/json" }
      }
    );

    const data = response.data;

    if (data.codigo !== 1) {
      return res.json({ erro: data.msg });
    }

    // salva histórico se logado
    if (usuario_id) {
      await pool.query(
        "INSERT INTO consultas (usuario_id, placa, valor_pago, dados_json, tipo) VALUES ($1,$2,$3,$4,$5)",
        [usuario_id, placaFormatada, 0, data]
      );
    }

    res.json(data);

  } catch (error) {

    console.log("ERRO FIPE:", error.response?.data || error.message);

    res.status(500).json({
      erro: error.response?.data?.msg || "Erro ao consultar placa"
    });
  }

});

/* =============================
   HISTÓRICO
============================= */

app.get("/api/historico", autenticar, async (req, res) => {

  const usuario_id = req.usuario.id;

  try {

    const consultas = await pool.query(
      `SELECT placa, valor_pago, criado_em, dados_json, tipo
       FROM consultas
       WHERE usuario_id = $1
       ORDER BY criado_em DESC`,
      [usuario_id]
    );

    res.json(consultas.rows);

  } catch (error) {
    res.status(500).json({ erro: "Erro ao buscar histórico" });
  }

});

app.get("/api/usuario/:id", async (req, res) => {
  const { id } = req.params;

  try {
    const usuario = await pool.query(
      "SELECT id, nome, sobrenome, email, saldo FROM usuarios WHERE id = $1",
      [id]
    );

    if (!usuario.rows.length) {
      return res.status(404).json({ erro: "Usuário não encontrado" });
    }

    res.json(usuario.rows[0]);

  } catch (error) {
    res.status(500).json({ erro: "Erro interno" });
  }
});

/* =============================
   CONSULTA BANCÁRIA (R$ 79,90)
============================= */

app.post("/api/consulta-bancaria", autenticar, consultaLimiter, antiAbusoConsulta, async (req, res) => {

  try {

    const { placa, nome, sobrenome, whatsapp, email, } = req.body;
    const userId = req.usuario.id;
    const VALOR = 79.90;

    const usuario = await pool.query(
      "SELECT saldo, bloqueado FROM usuarios WHERE id = $1",
      [userId]
    );

    if (!usuario.rows.length)
      return res.status(404).json({ erro: "Usuário não encontrado" });

    const saldo = Number(usuario.rows[0].saldo);

    if (usuario.rows[0].bloqueado)
      return res.status(403).json({ erro: "Conta bloqueada" });

    if (saldo < VALOR)
      return res.status(403).json({ erro: "Saldo insuficiente" });

    await pool.query("BEGIN");

    await pool.query(
      "UPDATE usuarios SET saldo = saldo - $1 WHERE id = $2",
      [VALOR, userId]
    );

    await pool.query(
      `INSERT INTO consultas_bancarias 
      (usuario_id, placa, nome, sobrenome, whatsapp, email, valor_pago)
      VALUES ($1,$2,$3,$4,$5,$6,$7)`,
      [userId, placa, nome, sobrenome, whatsapp, email, VALOR]
    );

    await pool.query("COMMIT");

    // 📩 ENVIA EMAIL
    await transporter.sendMail({

      from: `"Fipe Total" <${process.env.EMAIL_USER}>`,
      to: `${email}, fipetotal@gmail.com`,

      subject: "Consulta Bancária Recebida",

      html: `
        <h2>Consulta Bancária Recebida</h2>

        <p>Olá ${nome},</p>

        <p>Recebemos sua solicitação de consulta bancária.</p>

        <p><b>Placa:</b> ${placa}</p>

        <p>Nosso time irá analisar e enviar o resultado em até 2 horas.</p>

        <p>Equipe Fipe Total</p>
      `
    });

    res.json({ sucesso: true });

  } catch (error) {

    try {
      await pool.query("ROLLBACK");
    } catch { }

    console.log("Erro consulta bancária:", error);

    res.status(500).json({ erro: "Erro interno do servidor" });

  }

});

app.post("/api/admin/adicionar-saldo", autenticar, verificarAdmin, async (req, res) => {

  const { userId, valor } = req.body;

  if (!userId || !valor) {
    return res.status(400).json({ erro: "Dados inválidos" });
  }

  try {

    await pool.query(`
            UPDATE usuarios
            SET saldo = saldo + $1
            WHERE id = $2
        `, [valor, userId]);

    res.json({ sucesso: true });

  } catch (err) {
    console.error(err);
    res.status(500).json({ erro: "Erro ao adicionar saldo" });
  }

});

app.post("/api/admin/remover-saldo", autenticar, verificarAdmin, async (req, res) => {

  const { userId, valor } = req.body;

  try {

    await pool.query(`
            UPDATE usuarios
            SET saldo = saldo - $1
            WHERE id = $2
        `, [valor, userId]);

    res.json({ sucesso: true });

  } catch (err) {
    console.error(err);
    res.status(500).json({ erro: "Erro ao remover saldo" });
  }

});

app.get("/api/admin/consultas-bancarias", autenticar, verificarAdmin, async (req, res) => {

  try {

    const consultas = await pool.query(`
      SELECT 
      c.id,
      c.placa,
      c.nome,
      c.sobrenome,
      c.whatsapp,
      c.email,
      c.valor_pago,
      c.criado_em,
      u.nome AS usuario_nome,
      u.email AS usuario_email

      FROM consultas_bancarias c

      JOIN usuarios u 
      ON u.id = c.usuario_id

      ORDER BY c.criado_em DESC
      LIMIT 100
    `);

    res.json(consultas.rows);

  } catch (err) {

    console.log(err);

    res.status(500).json({
      erro: "Erro ao buscar consultas bancárias"
    });

  }

});

app.post("/api/admin/bloquear", autenticar, verificarAdmin, async (req, res) => {

  const { userId } = req.body;

  try {

    await pool.query(`
            UPDATE usuarios
            SET bloqueado = TRUE
            WHERE id = $1
        `, [userId]);

    res.json({ sucesso: true });

  } catch (err) {
    console.error(err);
    res.status(500).json({ erro: "Erro ao bloquear usuário" });
  }

});

app.post("/api/admin/desbloquear", autenticar, verificarAdmin, async (req, res) => {

  const { userId } = req.body;

  try {

    await pool.query(`
            UPDATE usuarios
            SET bloqueado = FALSE
            WHERE id = $1
        `, [userId]);

    res.json({ sucesso: true });

  } catch (err) {
    console.error(err);
    res.status(500).json({ erro: "Erro ao desbloquear usuário" });
  }

});

app.post("/api/admin/resetar-senha", autenticar, verificarAdmin, async (req, res) => {

  const { userId, novaSenha } = req.body;

  try {

    const senhaHash = await bcrypt.hash(novaSenha, 10);

    await pool.query(`
            UPDATE usuarios
            SET senha = $1
            WHERE id = $2
        `, [senhaHash, userId]);

    res.json({ sucesso: true });

  } catch (err) {
    console.error(err);
    res.status(500).json({ erro: "Erro ao resetar senha" });
  }

});

app.get("/api/me", autenticar, async (req, res) => {
  try {

    const usuario = await pool.query(
      "SELECT id, nome, email, is_admin FROM usuarios WHERE id = $1",
      [req.usuario.id]
    );

    if (!usuario.rows.length) {
      return res.status(404).json({ erro: "Usuário não encontrado" });
    }

    res.json(usuario.rows[0]);

  } catch (err) {
    res.status(500).json({ erro: "Erro interno" });
  }
});

app.post("/api/admin/excluir-usuario", autenticar, verificarAdmin, async (req, res) => {

  try {

    const { userId } = req.body;

    await pool.query(
      "DELETE FROM usuarios WHERE id = $1",
      [userId]
    );
    res.json({ sucesso: true });

  } catch (err) {

    res.status(500).json({ erro: "Erro ao excluir usuário" });

  }

});

app.get("/api/admin/stats", autenticar, verificarAdmin, async (req, res) => {

  try {

    const usuarios = await pool.query(
      "SELECT COUNT(*) FROM usuarios"
    );

    const bloqueados = await pool.query(
      "SELECT COUNT(*) FROM usuarios WHERE bloqueado = TRUE"
    );

    const saldo = await pool.query(
      "SELECT SUM(saldo) FROM usuarios"
    );

    const consultas = await pool.query(
      "SELECT COUNT(*) FROM consultas"
    );

    const faturamento = await pool.query(
      "SELECT SUM(valor_pago) FROM consultas"
    );

    res.json({
      totalUsuarios: Number(usuarios.rows[0].count),
      usuariosBloqueados: Number(bloqueados.rows[0].count),
      saldoSistema: Number(saldo.rows[0].sum || 0),
      totalConsultas: Number(consultas.rows[0].count),
      faturamento: Number(faturamento.rows[0].sum || 0)
    });

  } catch (err) {

    console.log(err);

    res.status(500).json({
      erro: "Erro ao carregar stats"
    });

  }

});

app.get("/api/admin/pagamentos", autenticar, verificarAdmin, async (req, res) => {

  try {

    const pagamentos = await pool.query(`
        SELECT p.id, p.valor, p.payment_id, p.criado_em,
        u.nome, u.email
        FROM pagamentos p
        JOIN usuarios u ON u.id = p.usuario_id
        ORDER BY p.criado_em DESC
    `);

    res.json(pagamentos.rows);

  } catch (err) {

    res.status(500).json({ erro: "Erro ao buscar pagamentos" });

  }

});

app.get("/api/admin/consultas", autenticar, verificarAdmin, async (req, res) => {

  const consultas = await pool.query(`
        SELECT c.id, c.placa, c.valor_pago, c.criado_em,
        u.nome, u.email
        FROM consultas c
        JOIN usuarios u ON u.id = c.usuario_id
        ORDER BY c.criado_em DESC
    `);

  res.json(consultas.rows);

});

/* =============================
   LISTAR USUÁRIOS (ADMIN)
============================= */

app.get("/api/admin/usuarios", autenticar, verificarAdmin, async (req, res) => {

  try {

    const usuarios = await pool.query(`
      SELECT 
      id,
      nome,
      email,
      saldo,
      bloqueado
      FROM usuarios
      ORDER BY id DESC
    `);

    res.json(usuarios.rows);

  } catch (err) {

    console.log(err);

    res.status(500).json({
      erro: "Erro ao buscar usuários"
    });

  }

});

/* =============================
   TOP CLIENTES
============================= */

app.get("/api/admin/top-clientes", autenticar, verificarAdmin, async (req, res) => {

  try {

    const result = await pool.query(`
      SELECT 
      u.id,
      u.nome,
      u.email,
      COUNT(c.id) AS total_consultas,
      SUM(c.valor_pago) AS total_gasto

      FROM usuarios u

      JOIN consultas c 
      ON u.id = c.usuario_id

      GROUP BY u.id

      ORDER BY total_gasto DESC

      LIMIT 10
    `);

    res.json(result.rows);

  } catch (err) {

    res.status(500).json({
      erro: "Erro ao buscar ranking"
    });

  }

});

app.post("/api/recuperar-senha", async (req, res) => {

  const { email } = req.body;

  try {

    const usuario = await pool.query(
      "SELECT id, nome FROM usuarios WHERE email = $1",
      [email]
    );

    if (!usuario.rows.length) {
      return res.json({ sucesso: true });
      // não revela se email existe
    }

    const user = usuario.rows[0];

    const token = jwt.sign(
      { id: user.id },
      process.env.JWT_SECRET,
      { expiresIn: "15m" }
    );

    const link = `https://engemafer.com.br/nova-senha.html?token=${token}`;

    await transporter.sendMail({

      from: `"Fipe Total" <${process.env.EMAIL_USER}>`,
      to: email,

      subject: "Recuperação de senha",

      html: `
      <h2>Recuperação de senha</h2>

      <p>Olá ${user.nome},</p>

      <p>Clique no botão abaixo para redefinir sua senha.</p>

      <a href="${link}" 
      style="
      background:#0066b3;
      color:white;
      padding:12px 25px;
      border-radius:8px;
      text-decoration:none;
      font-weight:bold;">
      Redefinir senha
      </a>

      <p>Esse link expira em 15 minutos.</p>

      <p>Se você não solicitou, ignore este email.</p>
      `
    });

    res.json({ sucesso: true });

  } catch (error) {

    res.status(500).json({ erro: "Erro interno" });

  }

});

app.post("/api/nova-senha", async (req, res) => {

  const { token, senha } = req.body;

  try {

    const decoded = jwt.verify(
      token,
      process.env.JWT_SECRET
    );

    const senhaHash = await bcrypt.hash(senha, 10);

    await pool.query(
      "UPDATE usuarios SET senha = $1 WHERE id = $2",
      [senhaHash, decoded.id]
    );

    res.json({ sucesso: true });

  } catch (error) {

    res.status(400).json({ erro: "Token inválido ou expirado" });

  }

});

/* =============================
   SERVIDOR
============================= */

const PORT = process.env.PORT || 3000;

app.listen(PORT, "0.0.0.0", () => {
  console.log(`Servidor rodando na porta ${PORT}`);
});

