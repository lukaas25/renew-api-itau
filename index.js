require('dotenv').config();
const axios = require('axios');
const fs = require('fs');
const https = require('https');
const { execSync } = require('child_process');

const {
  CLIENT_ID,
  CLIENT_SECRET,
  NOME_SISTEMA,
  CIDADE,
  ESTADO,
  PAIS,
  CERT_ATUAL,
  KEY_ATUAL
} = process.env;

if (!CLIENT_ID || !CLIENT_SECRET) {
  throw new Error("CLIENT_ID e CLIENT_SECRET são obrigatórios.");
}

if (!CERT_ATUAL || !KEY_ATUAL) {
  throw new Error("CERT_ATUAL e KEY_ATUAL são obrigatórios (certificado e chave atuais para mTLS).");
}

const KEY_FILE = './chave_privada.key';
const CSR_FILE = './request.csr';
const CERT_FILE = './certificado_novo.crt';

const sleep = (ms) => new Promise(resolve => setTimeout(resolve, ms));

/**
 * 1️⃣ Gerar CSR e chave privada
 */
function gerarCSR() {
  console.log('Gerando CSR...');

  const comando = `openssl req -new -subj "/CN=${CLIENT_ID}/OU=${NOME_SISTEMA}/L=${CIDADE}/ST=${ESTADO}/C=${PAIS}" -out ${CSR_FILE} -nodes -sha512 -newkey rsa:2048 -keyout ${KEY_FILE}`;

  execSync(comando);
  console.log('CSR e chave privada gerados.');

  // Validar CSR gerado
  const validacao = execSync(`openssl req -in ${CSR_FILE} -noout -subject`).toString();
  console.log('Subject do CSR:', validacao.trim());
}

/**
 */
function criarHttpsAgent() {
  return new https.Agent({
    cert: fs.readFileSync(CERT_ATUAL),
    key: fs.readFileSync(KEY_ATUAL),
    keepAlive: true,
    rejectUnauthorized: false
  });
}

async function obterAccessToken() {
  console.log('Solicitando access_token...');

  const httpsAgent = criarHttpsAgent();

  const response = await axios.post(
    'https://sts.itau.com.br/api/oauth/token',
    {
      grant_type: 'client_credentials',
      client_id: CLIENT_ID,
      client_secret: CLIENT_SECRET
    },
    {
      httpsAgent,
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded',
        'x-itau-correlationID': '1',
        'x-itau-flowID': '2'
      }
    }
  );

  console.log('Access token obtido.');
  console.log('Token:', response.data.access_token);
  return response.data.access_token;
}

/**
 * 3️⃣ Enviar CSR para renovação
 */
async function renovarCertificado(token) {
  console.log('Enviando CSR para renovação...');

  const csrContent = fs.readFileSync(CSR_FILE, 'utf8');
  const httpsAgent = criarHttpsAgent();

  const response = await axios.post(
    'https://sts.itau.com.br/seguranca/v2/certificado/renovacao',
    csrContent,
    {
      httpsAgent,
      headers: {
        'Authorization': `Bearer ${token}`,
        'Content-Type': 'text/plain',
        'x-itau-force-cert': 'true'
      }
    }
  );

  fs.writeFileSync(CERT_FILE, response.data);

  console.log('Certificado renovado com sucesso.');
  console.log(`Arquivo salvo em: ${CERT_FILE}`);
}

/**
 * 🚀 Execução principal
 */
async function main() {
  try {
    await gerarCSR();
    await sleep(2000);
    const token = await obterAccessToken();
    await sleep(2000);
    await renovarCertificado(token);
  } catch (error) {
    console.error('Erro na renovação:', error.response?.data || error.message);
  }
}

main();