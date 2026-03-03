require("dotenv").config();
const express = require("express");
const axios = require("axios");
const cors = require("cors");
const { Pool } = require("pg");
const { MercadoPagoConfig, Preference, Payment } = require("mercadopago");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");

const app = express();

app.use(cors());
app.use(express.json());

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
   RETURNING id, nome, sobrenome, email, saldo`,
      [nome, sobrenome, telefone, email, senhaHash, 3]
    );

    res.json(novoUsuario.rows[0]);

  } catch (error) {
    res.status(500).json({ erro: "Erro interno do servidor" });
  }
});

/* =============================
   LOGIN
============================= */

app.post("/api/login", async (req, res) => {
  const { email, senha } = req.body;

  try {
    console.log("Email recebido:", email);

    const result = await pool.query(
      "SELECT * FROM usuarios WHERE email = $1",
      [email]
    );

    console.log("Resultado banco:", result.rows);

    if (result.rows.length === 0) {
      return res.status(400).json({ erro: "Usuário não encontrado" });
    }

    const usuario = result.rows[0];

    const senhaValida = await bcrypt.compare(senha, usuario.senha);

    if (!senhaValida) {
      return res.status(400).json({ erro: "Senha incorreta" });
    }

    const token = jwt.sign(
      { id: usuario.id, is_admin: usuario.is_admin },
      process.env.JWT_SECRET || "segredo_super",
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
    res.status(500).json({ erro: "Erro no servidor" });
  }
});

/* =============================
   CRIAR PAGAMENTO
============================= */

app.post("/api/criar-pagamento", async (req, res) => {

  try {

    const { valor, userId } = req.body;

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
        notification_url: "https://fip-total-backend.onrender.com/api/webhook-mercadopago",
        back_urls: {
          success: "https://engemafer.com.br/sucesso.html",
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

app.post("/api/proprietario-atual", async (req, res) => {

  try {

    const { placa, userId } = req.body;
    const VALOR = 11.99;

    const usuario = await pool.query(
      "SELECT saldo FROM usuarios WHERE id = $1",
      [userId]
    );

    if (!usuario.rows.length)
      return res.status(404).json({ erro: "Usuário não encontrado" });

    const saldo = Number(usuario.rows[0].saldo);

    if (saldo < VALOR)
      return res.status(403).json({ erro: "Saldo insuficiente" });

    const response = await axios.post(
      "https://ws2.checkpro.com.br/servicejson.asmx/ConsultaProprietarioAtualPorPlaca",
      new URLSearchParams({
        cpfUsuario: process.env.CHECKPRO_CPF,
        senhaUsuario: process.env.CHECKPRO_SENHA,
        placa: placa.toUpperCase().replace(/[^A-Z0-9]/g, "")
      }),
      { headers: { "Content-Type": "application/x-www-form-urlencoded" } }
    );

    const data = response.data;

    console.log("Resposta CheckPro:", data);

    if (String(data.StatusRetorno) !== "1")
      return res.json({ erro: data.MensagemRetorno });

    await pool.query(
      "UPDATE usuarios SET saldo = saldo - $1 WHERE id = $2",
      [VALOR, userId]
    );

    await pool.query(
      "INSERT INTO consultas (usuario_id, placa, valor_pago, dados_json) VALUES ($1,$2,$3,$4)",
      [userId, placaFormatada, VALOR, data]
    );
    res.json({
      sucesso: true,
      dados: data,
      novoSaldo: saldo - VALOR
    });

  } catch (error) {
    console.log("ERRO DETALHADO CHECKPRO:");
    console.log(error.response?.data || error.message);

    res.status(500).json({
      erro: "Erro interno do servidor",
      detalhe: error.response?.data || error.message
    });
  }

});

/* =============================
   CONSULTA COMPLETA (R$54,90)
============================= */

app.post("/api/consulta-completa", async (req, res) => {

  try {

    const { placa, userId } = req.body;
    const VALOR = Number(54.90);

    const usuario = await pool.query(
      "SELECT saldo FROM usuarios WHERE id = $1",
      [userId]
    );

    if (!usuario.rows.length)
      return res.status(404).json({ erro: "Usuário não encontrado" });

    const saldo = Number(usuario.rows[0].saldo);

    if (saldo < VALOR)
      return res.status(403).json({ erro: "Saldo insuficiente" });

    const placaFormatada = placa.toUpperCase().replace(/[^A-Z0-9]/g, "");

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

    await pool.query("ROLLBACK");

    console.log("ERRO DETALHADO CONSULTA COMPLETA:");
    console.log(error.response?.data || error.message);

    res.status(500).json({
      erro: "Erro interno do servidor",
      detalhe: error.response?.data || error.message
    });
  }

});

/* =============================
   CONSULTA FIPE (GRÁTIS)
============================= */

app.get("/api/placafipe/:placa/:usuario_id?", async (req, res) => {

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
        "INSERT INTO consultas (usuario_id, placa, valor_pago, dados_json) VALUES ($1,$2,$3,$4)",
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

app.get("/api/historico/:usuario_id", async (req, res) => {

  const { usuario_id } = req.params;

  try {

    const consultas = await pool.query(
      `SELECT placa, valor_pago, criado_em, dados_json
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

app.post("/api/consulta-bancaria", async (req, res) => {

  try {

    const { placa, nome, sobrenome, whatsapp, email, userId } = req.body;
    const VALOR = 79.90;

    const usuario = await pool.query(
      "SELECT saldo FROM usuarios WHERE id = $1",
      [userId]
    );

    if (!usuario.rows.length)
      return res.status(404).json({ erro: "Usuário não encontrado" });

    const saldo = Number(usuario.rows[0].saldo);

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

    res.json({ sucesso: true });

  } catch (error) {

    await pool.query("ROLLBACK");

    res.status(500).json({ erro: "Erro interno do servidor" });
  }

});

function autenticar(req, res, next) {

  const authHeader = req.headers.authorization;

  if (!authHeader) {
    return res.status(401).json({ erro: "Token não fornecido" });
  }

  const token = authHeader.split(" ")[1];

  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    req.usuario = decoded;
    next();
  } catch (err) {
    return res.status(401).json({ erro: "Token inválido" });
  }
}

function verificarAdmin(req, res, next) {

  if (!req.usuario || !req.usuario.is_admin) {
    return res.status(403).json({ erro: "Acesso negado" });
  }

  next();
}

app.get("/api/admin/usuarios", autenticar, verificarAdmin, async (req, res) => {

  try {

    const result = await pool.query(`
            SELECT id, nome, email, saldo, criado_em, bloqueado
            FROM usuarios
            ORDER BY criado_em DESC
        `);

    res.json(result.rows);

  } catch (err) {
    console.error(err);
    res.status(500).json({ erro: "Erro ao buscar usuários" });
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


/* =============================
   SERVIDOR
============================= */

const PORT = process.env.PORT || 3000;

app.listen(PORT, "0.0.0.0", () => {
  console.log(`Servidor rodando na porta ${PORT}`);
});