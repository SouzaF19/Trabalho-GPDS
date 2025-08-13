<?php
// Define as regras de comunicação da API, permitindo que o frontend acesse este backend
header("Access-Control-Allow-Origin: *");
header("Content-Type: application/json; charset=UTF-8");
header("Access-Control-Allow-Methods: POST, GET, OPTIONS");
header("Access-Control-Allow-Headers: Content-Type, Access-Control-Allow-Headers, Authorization, X-Requested-With");

// Responde a uma verificação inicial que o navegador faz
if ($_SERVER['REQUEST_METHOD'] == 'OPTIONS') 
{
    http_response_code(200);
    exit();
}

// Inicia a sessao para lembrar qual usuário está logado.
session_start();
// Inclui o arquivo de conexão com o banco de dados
require_once '../config/Database.php';

// Estabelece a conexão com o banco de dados
$database = new Database();
$conexao = $database->conectar();

// Pega a ação desejada da URL (ex: ?action=login)
$acao = isset($_GET['action']) ? $_GET['action'] : '';
// Pega o ID do evento da URL, se houver.
$idEvento = isset($_GET['eventId']) ? intval($_GET['eventId']) : null;
// Pega os dados JSON enviados pelo frontend (ex: email e senha).
$dados = json_decode(file_get_contents("php://input"));

// Função para enviar uma resposta em JSON e encerrar o script.
function enviar_resposta($dados, $codigo_status = 200) 
{
    http_response_code($codigo_status);
    echo json_encode($dados);
    exit();
}

// Função que verifica se o usuário está logado antes de permitir uma ação.
function exigir_login() 
{
    if (!isset($_SESSION['user_id'])) 
    {
        enviar_resposta(['message' => 'Acesso não autorizado.'], 401);
    }
}

// Roteador: Direciona a requisição para a função correta com base na acao.
switch ($acao) 
{
    case 'login':
        processarLogin($conexao, $dados);
        break;
    case 'register':
        processarCadastro($conexao, $dados);
        break;
    case 'get_events':
        obterEventos($conexao);
        break;
    case 'get_event_details':
        if ($idEvento) obterDetalhesEvento($conexao, $idEvento);
        else enviar_resposta(['message' => 'ID do evento não fornecido.'], 400);
        break;
    case 'logout':
        exigir_login();
        processarLogout();
        break;
    case 'check_session':
        verificarSessao($conexao);
        break;
    case 'update_profile':
        exigir_login();
        atualizarPerfil($conexao, $dados);
        break;
    default:
        enviar_resposta(['message' => 'Ação inválida.'], 400);
        break;
}

// Funções que executam as ações

// Valida o login de um usuario.
function processarLogin($conexao, $dados) 
{
    // Busca o usuário pelo email.
    $stmt = $conexao->prepare("SELECT id, nome, email, tipo, senha FROM usuarios WHERE email = :email LIMIT 1");
    $stmt->bindParam(':email', $dados->email);
    $stmt->execute();
    $usuario = $stmt->fetch(PDO::FETCH_ASSOC);

    // Verifica se o usuário existe e se a senha esta correta.
    if ($usuario && password_verify($dados->password, $usuario['senha'])) 
    {
        // Se sim, inicia a sessão e envia os dados do usuário de volta.
        $_SESSION['user_id'] = $usuario['id'];
        $_SESSION['user_name'] = $usuario['nome'];
        $_SESSION['user_type'] = $usuario['tipo'];
        unset($usuario['senha']);
        enviar_resposta(['success' => true, 'user' => $usuario]);
    } 
    else 
    {
        // Se não, envia uma mensagem de erro.
        enviar_resposta(['message' => 'Email ou senha incorretos.'], 401);
    }
}

// Cadastra um novo usuario no banco de dados.
function processarCadastro($conexao, $dados) 
{
    // Verifica se o email já está cadastrado.
    $stmt = $conexao->prepare("SELECT id FROM usuarios WHERE email = :email");
    $stmt->bindParam(':email', $dados->email);
    $stmt->execute();
    if ($stmt->rowCount() > 0) enviar_resposta(['message' => 'Este email já está em uso.'], 409);
    
    // Insere o novo usuario no banco com a senha criptografada
    $sql = "INSERT INTO usuarios (nome, email, senha, tipo) VALUES (:nome, :email, :senha, :tipo)";
    $stmt = $conexao->prepare($sql);
    $senha_criptografada = password_hash($dados->password, PASSWORD_DEFAULT);
    $stmt->bindParam(':nome', $dados->name);
    $stmt->bindParam(':email', $dados->email);
    $stmt->bindParam(':senha', $senha_criptografada);
    $stmt->bindParam(':tipo', $dados->type);

    // Se o cadastro funcionar, ja inicia a sessão para o novo usuário
    if ($stmt->execute()) 
    {
        $id_usuario = $conexao->lastInsertId();
        $_SESSION['user_id'] = $id_usuario;
        $_SESSION['user_name'] = $dados->name;
        $_SESSION['user_type'] = $dados->type;
        $usuario = ['id' => $id_usuario, 'nome' => $dados->name, 'email' => $dados->email, 'tipo' => $dados->type];
        enviar_resposta(['success' => true, 'user' => $usuario]);
    } 
    else 
    {
        enviar_resposta(['message' => 'Erro ao registrar usuário.'], 500);
    }
}

// Encerra a sessão do usuario
function processarLogout() 
{
    session_destroy();
    enviar_resposta(['success' => true, 'message' => 'Logout realizado com sucesso.']);
}

// Verifica se existe uma sessão ativa
function verificarSessao($conexao) 
{
    if (isset($_SESSION['user_id'])) 
    {
        $stmt = $conexao->prepare("SELECT id, nome, email, tipo FROM usuarios WHERE id = :id");
        $stmt->bindParam(':id', $_SESSION['user_id']);
        $stmt->execute();
        $usuario = $stmt->fetch(PDO::FETCH_ASSOC);
        if ($usuario) enviar_resposta(['loggedIn' => true, 'user' => $usuario]);
    }
    enviar_resposta(['loggedIn' => false]);
}

// Busca todos os eventos no banco de dados
function obterEventos($conexao) 
{
    $stmt = $conexao->prepare("SELECT id, nome, data, local, is_online, imagem_url FROM eventos ORDER BY data ASC");
    $stmt->execute();
    enviar_resposta($stmt->fetchAll(PDO::FETCH_ASSOC));
}

// Busca os detalhes de um evento especifico e sua programação
function obterDetalhesEvento($conexao, $idEvento) 
{
    // Busca o evento.
    $stmt = $conexao->prepare("SELECT * FROM eventos WHERE id = :id");
    $stmt->bindParam(':id', $idEvento);
    $stmt->execute();
    $evento = $stmt->fetch(PDO::FETCH_ASSOC);
    if (!$evento) enviar_resposta(['message' => 'Evento não encontrado.'], 404);

    // Busca a programação do evento.
    $stmt = $conexao->prepare("SELECT horario, titulo FROM programacao WHERE id_evento = :id_evento ORDER BY horario ASC");
    $stmt->bindParam(':id_evento', $idEvento);
    $stmt->execute();
    $evento['program'] = $stmt->fetchAll(PDO::FETCH_ASSOC);
    enviar_resposta($evento);
}

// Atualiza as informações de um usuário no banco de dados
function atualizarPerfil($conexao, $dados) 
{
    // Verifica se o novo email já não está sendo usado por outra pessoa.
    $stmt = $conexao->prepare("SELECT id FROM usuarios WHERE email = :email AND id != :id");
    $stmt->execute(['email' => $dados->email, 'id' => $_SESSION['user_id']]);
    if ($stmt->rowCount() > 0) enviar_resposta(['message' => 'Este email já está em uso por outra conta.'], 409);

    // Se uma nova senha foi enviada, atualiza a senha.
    if (!empty($dados->password)) 
    {
        $sql = "UPDATE usuarios SET nome = :nome, email = :email, senha = :senha WHERE id = :id";
        $stmt = $conexao->prepare($sql);
        $senha_criptografada = password_hash($dados->password, PASSWORD_DEFAULT);
        $stmt->bindParam(':senha', $senha_criptografada);
    } 
    else 
    {
        // Senão, atualiza apenas nome e email.
        $sql = "UPDATE usuarios SET nome = :nome, email = :email WHERE id = :id";
        $stmt = $conexao->prepare($sql);
    }
    $stmt->bindParam(':nome', $dados->name);
    $stmt->bindParam(':email', $dados->email);
    $stmt->bindParam(':id', $_SESSION['user_id']);

    // Executa a atualizaçao e envia uma resposta.
    if ($stmt->execute()) 
    {
        $_SESSION['user_name'] = $dados->name;
        enviar_resposta(['success' => true, 'message' => 'Perfil atualizado com sucesso.']);
    } 
    else 
    {
        enviar_resposta(['message' => 'Erro ao atualizar o perfil.'], 500);
    }
}
?>
