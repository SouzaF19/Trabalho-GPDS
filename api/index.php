<?php
// Configura os cabeçalhos HTTP para a API
header("Access-Control-Allow-Origin: *");
header("Content-Type: application/json; charset=UTF-8");
header("Access-Control-Allow-Methods: POST, GET, OPTIONS, DELETE, PUT");
header("Access-Control-Allow-Headers: Content-Type, Access-Control-Allow-Headers, Authorization, X-Requested-With");

// Responde a requisiçoes do tipo OPTIONS
if ($_SERVER['REQUEST_METHOD'] == 'OPTIONS') 
{
    http_response_code(200);
    exit();
}

// Inicia a sessão, essencial para armazenar informações de login do usuario
session_start();

// Inclui o arquivo que contem a lógica de conexão com o banco de dados
require_once '../config/Database.php';

// Cria uma nova instância da classe Database e estabelece a conexão
$database = new Database();
$db = $database->connect();

// Obtém a ação desejada a partir da URL
$action = isset($_GET['action']) ? $_GET['action'] : '';
$eventId = isset($_GET['eventId']) ? intval($_GET['eventId']) : null;

// Lê e decodifica os dados JSON enviados no corpo da requisição
$data = json_decode(file_get_contents("php://input"));

// Função utilitária para padronizar o envio de respostas JSON
function send_response($data, $status_code = 200) 
{
    http_response_code($status_code);
    echo json_encode($data);
    exit(); // Encerra a execução do script após enviar a resposta
}

// Função para verificar se um usuário está logado, bloqueando o acesso se não estiver
function require_login() 
{
    if (!isset($_SESSION['user_id'])) 
    {
        send_response(['message' => 'Acesso não autorizado. Por favor, faça login.'], 401);
    }
}

// Função para verificar se o usuário logado é do tipo 'ORGANIZADOR'
function require_organizer() 
{
    require_login(); // Primeiro, garante que o usuário está logado
    if ($_SESSION['user_type'] !== 'ORGANIZADOR') 
    {
        send_response(['message' => 'Acesso restrito a organizadores.'], 403);
    }
}


// Roteador principal da API: com base na action, chama a função correspondente
switch ($action) 
{
    // --- Ações Públicas ---
    case 'login':
        handleLogin($db, $data);
        break;
    case 'register':
        handleRegister($db, $data);
        break;
    case 'get_events':
        getEvents($db);
        break;
    case 'get_event_details':
        if ($eventId) getEventDetails($db, $eventId);
        else send_response(['message' => 'ID do evento não fornecido.'], 400);
        break;

    // --- Ações que Exigem Login ---
    case 'logout':
        require_login();
        handleLogout();
        break;
    case 'check_session':
        checkSession($db);
        break;
    case 'update_profile':
        require_login();
        updateProfile($db, $data);
        break;
    case 'register_for_event':
        require_login();
        registerForEvent($db, $data);
        break;
    case 'submit_work':
        require_login();
        handleSubmitWork($db, $_POST, $_FILES);
        break;
    case 'rate_event':
        require_login();
        rateEvent($db, $data);
        break;
    case 'get_my_inscriptions':
        require_login();
        getMyInscriptions($db);
        break;
    case 'get_my_certificates':
        require_login();
        getMyCertificates($db);
        break;

    // --- Ações Restritas a Organizadores ---
    case 'create_update_event':
        require_organizer();
        createOrUpdateEvent($db, $data);
        break;
    case 'get_my_organized_events':
        require_organizer();
        getMyOrganizedEvents($db);
        break;
    case 'close_event':
        require_organizer();
        closeEvent($db, $data);
        break;
    case 'delete_event':
        require_organizer();
        deleteEvent($db, $data);
        break;
    case 'get_works_for_review':
        require_organizer();
        if ($eventId) getWorksForReview($db, $eventId);
        else send_response(['message' => 'ID do evento não fornecido.'], 400);
        break;
    case 'save_work_review':
        require_organizer();
        saveWorkReview($db, $data);
        break;
    case 'get_attendees_for_certificate':
        require_organizer();
        if ($eventId) getAttendeesForCertificate($db, $eventId);
        else send_response(['message' => 'ID do evento não fornecido.'], 400);
        break;
    case 'issue_certificate':
        require_organizer();
        issueCertificate($db, $data);
        break;
    case 'get_event_report':
        require_organizer();
        if ($eventId) getEventReport($db, $eventId);
        else send_response(['message' => 'ID do evento não fornecido.'], 400);
        break;

    default:
        send_response(['message' => 'Ação não especificada ou inválida.'], 400);
        break;
}

// Valida as credenciais do usuário e cria uma sessão.
function handleLogin($db, $data) 
{
    if (empty($data->email) || empty($data->password)) 
    {
        send_response(['message' => 'Email e senha são obrigatórios.'], 400);
    }
    $stmt = $db->prepare("SELECT id, nome, email, tipo, senha FROM usuarios WHERE email = :email LIMIT 1");
    $stmt->bindParam(':email', $data->email);
    $stmt->execute();
    $user = $stmt->fetch(PDO::FETCH_ASSOC);

    if ($user && password_verify($data->password, $user['senha'])) 
    {
        $_SESSION['user_id'] = $user['id'];
        $_SESSION['user_name'] = $user['nome'];
        $_SESSION['user_type'] = $user['tipo'];
        unset($user['senha']); // Remove o hash da senha da resposta
        send_response(['success' => true, 'user' => $user]);
    } 
    else 
    {
        send_response(['message' => 'Email ou senha incorretos.'], 401);
    }
}

// Cria um novo usuário no banco de dados
function handleRegister($db, $data) 
{
    if (empty($data->name) || empty($data->email) || empty($data->password) || empty($data->type)) 
    {
        send_response(['message' => 'Todos os campos são obrigatórios.'], 400);
    }
    // Verifica se o email ja esta em uso
    $stmt = $db->prepare("SELECT id FROM usuarios WHERE email = :email");
    $stmt->bindParam(':email', $data->email);
    $stmt->execute();
    if ($stmt->rowCount() > 0) 
    {
        send_response(['message' => 'Este email já está em uso.'], 409);
    }

    $query = "INSERT INTO usuarios (nome, email, senha, tipo) VALUES (:nome, :email, :senha, :tipo)";
    $stmt = $db->prepare($query);
    $hashed_password = password_hash($data->password, PASSWORD_DEFAULT);
    $stmt->bindParam(':nome', $data->name);
    $stmt->bindParam(':email', $data->email);
    $stmt->bindParam(':senha', $hashed_password);
    $stmt->bindParam(':tipo', $data->type);

    if ($stmt->execute()) 
    {
        // Apos o registro, inicia a sessão para o novo usuário
        $user_id = $db->lastInsertId();
        $_SESSION['user_id'] = $user_id;
        $_SESSION['user_name'] = $data->name;
        $_SESSION['user_type'] = $data->type;
        $user = ['id' => $user_id, 'nome' => $data->name, 'email' => $data->email, 'tipo' => $data->type];
        send_response(['success' => true, 'user' => $user]);
    } 
    else 
    {
        send_response(['message' => 'Erro ao registrar usuário.'], 500);
    }
}

// Encerra a sessão do usuário.
function handleLogout() 
{
    session_destroy();
    send_response(['success' => true, 'message' => 'Logout realizado com sucesso.']);
}

// Verifica se existe uma sessão ativa e retorna os dados do usuário.
function checkSession($db) 
{
    if (isset($_SESSION['user_id'])) 
    {
        $stmt = $db->prepare("SELECT id, nome, email, tipo FROM usuarios WHERE id = :id");
        $stmt->bindParam(':id', $_SESSION['user_id']);
        $stmt->execute();
        $user = $stmt->fetch(PDO::FETCH_ASSOC);
        if ($user) 
        {
            send_response(['loggedIn' => true, 'user' => $user]);
        } 
        else
        {
            session_destroy();
            send_response(['loggedIn' => false]);
        }
    } 
    else 
    {
        send_response(['loggedIn' => false]);
    }
}

// Retorna a lista de eventos com status 'open'
function getEvents($db) 
{
    $stmt = $db->prepare("SELECT id, nome, data, local, is_online, imagem_url FROM eventos WHERE status = 'open' ORDER BY data ASC");
    $stmt->execute();
    send_response($stmt->fetchAll(PDO::FETCH_ASSOC));
}

// Retorna os detalhes completos de um evento específico
function getEventDetails($db, $eventId) 
{
    $stmt = $db->prepare("SELECT * FROM eventos WHERE id = :id");
    $stmt->bindParam(':id', $eventId);
    $stmt->execute();
    $event = $stmt->fetch(PDO::FETCH_ASSOC);
    if (!$event) send_response(['message' => 'Evento não encontrado.'], 404);

    // Busca a programação associada ao evento.
    $stmt = $db->prepare("SELECT horario, titulo FROM programacao WHERE id_evento = :id_evento ORDER BY horario ASC");
    $stmt->bindParam(':id_evento', $eventId);
    $stmt->execute();
    $event['program'] = $stmt->fetchAll(PDO::FETCH_ASSOC);

    // Se o usuário estiver logado, adiciona informações personalizadas (inscrição, trabalho, avaliação).
    if (isset($_SESSION['user_id'])) 
    {
        $userId = $_SESSION['user_id'];
        $stmt = $db->prepare("SELECT COUNT(*) as count FROM inscricoes WHERE id_usuario = :user_id AND id_evento = :event_id");
        $stmt->execute(['user_id' => $userId, 'event_id' => $eventId]);
        $event['isUserRegistered'] = $stmt->fetch()['count'] > 0;

        $stmt = $db->prepare("SELECT titulo, autores, nota, observacoes FROM trabalhos WHERE id_usuario = :user_id AND id_evento = :event_id");
        $stmt->execute(['user_id' => $userId, 'event_id' => $eventId]);
        $event['userWork'] = $stmt->fetch(PDO::FETCH_ASSOC) ?: null;

        $stmt = $db->prepare("SELECT estrelas, comentario FROM avaliacoes WHERE id_usuario = :user_id AND id_evento = :event_id");
        $stmt->execute(['user_id' => $userId, 'event_id' => $eventId]);
        $event['userRating'] = $stmt->fetch(PDO::FETCH_ASSOC) ?: null;
    }
    send_response($event);
}

// Cria um novo evento ou atualiza um existente, usando uma transação para garantir a integridade dos dados.
function createOrUpdateEvent($db, $data) 
{
    // Validação básica dos campos
    if (empty($data->name) || empty($data->date) || empty($data->location) || empty($data->description) || empty($data->speaker) || empty($data->workload)) 
    {
        send_response(['message' => 'Todos os campos principais são obrigatórios.'], 400);
    }

    $db->beginTransaction(); // Inicia a transação.
    try 
    {
        if (isset($data->id) && !empty($data->id)) 
        { // Se tem ID, ATUALIZA.
            $stmt = $db->prepare(
                "UPDATE eventos SET 
                    nome = :nome, 
                    data = :data, 
                    local = :local, 
                    palestrante = :palestrante, 
                    carga_horaria = :carga_horaria, 
                    is_online = :is_online, 
                    descricao = :descricao, 
                    imagem_url = :imagem_url, 
                    permite_submissao = :permite_submissao, 
                    info_revisor_formacao = :info_revisor_formacao 
                WHERE id = :id AND id_organizador = :id_organizador"
            );
            $stmt->bindParam(':id', $data->id, PDO::PARAM_INT);
        } 
        else 
        { // Se não tem ID, INSERE.
            $stmt = $db->prepare(
                "INSERT INTO eventos 
                    (id_organizador, nome, data, local, palestrante, carga_horaria, is_online, descricao, imagem_url, permite_submissao, info_revisor_formacao) 
                VALUES 
                    (:id_organizador, :nome, :data, :local, :palestrante, :carga_horaria, :is_online, :descricao, :imagem_url, :permite_submissao, :info_revisor_formacao)"
            );
        }
        
        // Prepara as variáveis para o bind
        $formation = $data->submissionReviewerInfo->formation ?? null;
        $imageUrl = !empty($data->image) ? $data->image : null;
        $isOnline = !empty($data->isOnline) ? $data->isOnline : false;
        $allowSubmission = !empty($data->allowWorkSubmission) ? $data->allowWorkSubmission : false;
        
        // VINCULA TODOS OS PARÂMETROS
        $stmt->bindParam(':id_organizador', $_SESSION['user_id'], PDO::PARAM_INT);
        $stmt->bindParam(':nome', $data->name);
        $stmt->bindParam(':data', $data->date);
        $stmt->bindParam(':local', $data->location);
        $stmt->bindParam(':palestrante', $data->speaker);
        $stmt->bindParam(':carga_horaria', $data->workload, PDO::PARAM_INT);
        $stmt->bindParam(':is_online', $isOnline, PDO::PARAM_BOOL);
        $stmt->bindParam(':descricao', $data->description);
        $stmt->bindParam(':imagem_url', $imageUrl);
        $stmt->bindParam(':permite_submissao', $allowSubmission, PDO::PARAM_BOOL);
        $stmt->bindParam(':info_revisor_formacao', $formation);
        
        $stmt->execute();
        
        $eventId = isset($data->id) && !empty($data->id) ? $data->id : $db->lastInsertId();

        // Limpa e reinsere a programação para simplificar a lógica.
        $stmt_delete_program = $db->prepare("DELETE FROM programacao WHERE id_evento = :id_evento");
        $stmt_delete_program->execute(['id_evento' => $eventId]);
        
        if (!empty($data->program)) 
        {
            $stmt_insert_program = $db->prepare("INSERT INTO programacao (id_evento, horario, titulo) VALUES (:id_evento, :horario, :titulo)");
            foreach ($data->program as $item) {
                // Garante que não está inserindo itens de programação vazios
                if (!empty($item->time) && !empty($item->title)) {
                    $stmt_insert_program->execute(['id_evento' => $eventId, 'horario' => $item->time, 'titulo' => $item->title]);
                }
            }
        }
        
        $db->commit(); // Confirma a transação se tudo deu certo
        send_response(['success' => true, 'message' => 'Evento salvo com sucesso.']);
    } 
    catch (Exception $e) 
    {
        $db->rollBack(); // Desfaz a transação em caso de erro
        // Retorna uma mensagem de erro mais detalhada para depuração
        send_response(['message' => 'Erro ao salvar o evento: ' . $e->getMessage()], 500);
    }
}


// Retorna os eventos criados pelo organizador logado
function getMyOrganizedEvents($db) 
{
    $stmt = $db->prepare("SELECT e.id, e.nome, e.status, (SELECT COUNT(*) FROM inscricoes i WHERE i.id_evento = e.id) as attendee_count FROM eventos e WHERE e.id_organizador = :id_organizador ORDER BY e.status, e.data DESC");
    $stmt->execute(['id_organizador' => $_SESSION['user_id']]);
    send_response($stmt->fetchAll(PDO::FETCH_ASSOC));
}

// Retorna os eventos nos quais o usuário está inscrito
function getMyInscriptions($db) 
{
    $stmt = $db->prepare("SELECT e.*, t.nota as nota_trabalho FROM eventos e JOIN inscricoes i ON e.id = i.id_evento LEFT JOIN trabalhos t ON e.id = t.id_evento AND i.id_usuario = t.id_usuario WHERE i.id_usuario = :id_usuario ORDER BY e.status, e.data DESC");
    $stmt->execute(['id_usuario' => $_SESSION['user_id']]);
    send_response($stmt->fetchAll(PDO::FETCH_ASSOC));
}

// Atualiza o perfil (nome, email, senha) do usuário logado
function updateProfile($db, $data) 
{
    if (empty($data->name) || empty($data->email)) 
    {
        send_response(['message' => 'Nome e email são obrigatórios.'], 400);
    }
    // Verifica se o email já está sendo usado por outro usuário.
    $stmt = $db->prepare("SELECT id FROM usuarios WHERE email = :email AND id != :id");
    $stmt->execute(['email' => $data->email, 'id' => $_SESSION['user_id']]);
    if ($stmt->rowCount() > 0) 
    {
        send_response(['message' => 'Este email já está em uso por outra conta.'], 409);
    }

    if (!empty($data->password)) 
    { // Se uma nova senha foi fornecida, atualiza.
        $query = "UPDATE usuarios SET nome = :nome, email = :email, senha = :senha WHERE id = :id";
        $stmt = $db->prepare($query);
        $hashed_password = password_hash($data->password, PASSWORD_DEFAULT);
        $stmt->bindParam(':senha', $hashed_password);
    } 
    else 
    { // Caso contrário, mantém a senha atual.
        $query = "UPDATE usuarios SET nome = :nome, email = :email WHERE id = :id";
        $stmt = $db->prepare($query);
    }
    $stmt->bindParam(':nome', $data->name);
    $stmt->bindParam(':email', $data->email);
    $stmt->bindParam(':id', $_SESSION['user_id']);

    if ($stmt->execute()) 
    {
        $_SESSION['user_name'] = $data->name;
        send_response(['success' => true, 'message' => 'Perfil atualizado com sucesso.']);
    } 
    else 
    {
        send_response(['message' => 'Erro ao atualizar o perfil.'], 500);
    }
}

// Inscreve o usuário logado em um evento.
function registerForEvent($db, $data) 
{
    if (empty($data->eventId)) 
    {
        send_response(['message' => 'ID do evento não fornecido.'], 400);
    }
    $stmt = $db->prepare("INSERT INTO inscricoes (id_usuario, id_evento) VALUES (:id_usuario, :id_evento)");
    try 
    {
        $stmt->execute(['id_usuario' => $_SESSION['user_id'], 'id_evento' => $data->eventId]);
        send_response(['success' => true, 'message' => 'Inscrição realizada com sucesso!']);
    } 
    catch (PDOException $e) 
    {
        if ($e->getCode() == 23000) 
        { // Trata erro de chave duplicada (já inscrito).
            send_response(['message' => 'Você já está inscrito neste evento.'], 409);
        } 
        else 
        {
            send_response(['message' => 'Erro ao realizar inscrição: ' . $e->getMessage()], 500);
        }
    }
}

// Lida com o upload do arquivo de um trabalho e salva os dados no banco.
function handleSubmitWork($db, $postData, $fileData) 
{
    if (empty($postData['eventId']) || empty($postData['title']) || !isset($fileData['workFile'])) 
    {
        send_response(['message' => 'Todos os campos e o arquivo são obrigatórios.'], 400);
    }
    if ($fileData['workFile']['error'] !== UPLOAD_ERR_OK) 
    {
        send_response(['message' => 'Erro no upload do arquivo.'], 400);
    }
    
    $uploadDir = '../uploads/';
    if (!is_dir($uploadDir)) mkdir($uploadDir, 0777, true);
    
    $fileName = time() . '_' . basename($fileData['workFile']['name']);
    $uploadFile = $uploadDir . $fileName;

    if (move_uploaded_file($fileData['workFile']['tmp_name'], $uploadFile)) 
    {
        $stmt = $db->prepare("INSERT INTO trabalhos (id_evento, id_usuario, titulo, autores, resumo, nome_arquivo) VALUES (:id_evento, :id_usuario, :titulo, :autores, :resumo, :nome_arquivo)");
        $stmt->execute([
            'id_evento' => $postData['eventId'], 'id_usuario' => $_SESSION['user_id'],
            'titulo' => $postData['title'], 'autores' => $postData['authors'],
            'resumo' => $postData['abstract'], 'nome_arquivo' => $fileName
        ]);
        send_response(['success' => true, 'message' => 'Trabalho enviado com sucesso!']);
    } 
    else 
    {
        send_response(['message' => 'Falha ao mover o arquivo enviado.'], 500);
    }
}

// Salva ou atualiza a avaliação (estrelas e comentário) de um evento.
function rateEvent($db, $data) 
{
    if (empty($data->eventId) || empty($data->stars)) 
    {
        send_response(['message' => 'ID do evento e avaliação são obrigatórios.'], 400);
    }
    $query = "INSERT INTO avaliacoes (id_evento, id_usuario, estrelas, comentario) VALUES (:id_evento, :id_usuario, :estrelas, :comentario) ON DUPLICATE KEY UPDATE estrelas = :estrelas, comentario = :comentario";
    $stmt = $db->prepare($query);
    $stmt->execute([
        'id_evento' => $data->eventId, 'id_usuario' => $_SESSION['user_id'],
        'estrelas' => $data->stars, 'comentario' => $data->comment
    ]);
    send_response(['success' => true, 'message' => 'Avaliação enviada com sucesso!']);
}

// Retorna os certificados do usuário logado.
function getMyCertificates($db) 
{
    $stmt = $db->prepare("SELECT c.*, e.nome as eventName, e.palestrante as speakerName, e.carga_horaria as workload FROM certificados c JOIN eventos e ON c.id_evento = e.id WHERE c.id_usuario = :id_usuario");
    $stmt->execute(['id_usuario' => $_SESSION['user_id']]);
    send_response($stmt->fetchAll(PDO::FETCH_ASSOC));
}

// Muda o status de um evento para 'closed'.
function closeEvent($db, $data) 
{
    if (empty($data->eventId)) send_response(['message' => 'ID do evento não fornecido.'], 400);
    $stmt = $db->prepare("UPDATE eventos SET status = 'closed' WHERE id = :id AND id_organizador = :id_organizador");
    $stmt->execute(['id' => $data->eventId, 'id_organizador' => $_SESSION['user_id']]);
    if ($stmt->rowCount() > 0) 
    {
        send_response(['success' => true, 'message' => 'Evento encerrado com sucesso.']);
    } 
    else 
    {
        send_response(['message' => 'Não foi possível encerrar o evento. Verifique se você é o organizador.'], 403);
    }
}

// Exclui um evento e seus dados relacionados (em cascata, se configurado no DB).
function deleteEvent($db, $data) 
{
    if (empty($data->eventId)) send_response(['message' => 'ID do evento não fornecido.'], 400);
    $stmt = $db->prepare("DELETE FROM eventos WHERE id = :id AND id_organizador = :id_organizador");
    $stmt->execute(['id' => $data->eventId, 'id_organizador' => $_SESSION['user_id']]);
    if ($stmt->rowCount() > 0) 
    {
        send_response(['success' => true, 'message' => 'Evento excluído com sucesso.']);
    } 
    else 
    {
        send_response(['message' => 'Não foi possível excluir o evento. Verifique se você é o organizador.'], 403);
    }
}

// Retorna os trabalhos submetidos para um evento para serem avaliados.
function getWorksForReview($db, $eventId) 
{
    $stmt = $db->prepare("SELECT t.*, u.nome as user_name FROM trabalhos t JOIN usuarios u ON t.id_usuario = u.id WHERE t.id_evento = :id_evento");
    $stmt->execute(['id_evento' => $eventId]);
    send_response($stmt->fetchAll(PDO::FETCH_ASSOC));
}

// Salva a nota e observações para um trabalho específico.
function saveWorkReview($db, $data) 
{
    if (empty($data->workId) || !isset($data->grade)) 
    {
        send_response(['message' => 'Dados insuficientes para salvar avaliação.'], 400);
    }
    $stmt = $db->prepare("UPDATE trabalhos SET nota = :nota, observacoes = :observacoes WHERE id = :id");
    $stmt->execute(['nota' => $data->grade, 'observacoes' => $data->observations, 'id' => $data->workId]);
    send_response(['success' => true, 'message' => 'Avaliação do trabalho salva com sucesso.']);
}

// Retorna a lista de participantes de um evento para a emissão de certificados.
function getAttendeesForCertificate($db, $eventId) 
{
    $stmt = $db->prepare("SELECT u.id, u.nome, u.email, (SELECT COUNT(*) FROM certificados c WHERE c.id_evento = i.id_evento AND c.id_usuario = i.id_usuario) as has_certificate FROM usuarios u JOIN inscricoes i ON u.id = i.id_usuario WHERE i.id_evento = :id_evento");
    $stmt->execute(['id_evento' => $eventId]);
    send_response($stmt->fetchAll(PDO::FETCH_ASSOC));
}

// Emite um certificado para um usuário em um evento.
function issueCertificate($db, $data) 
{
    if (empty($data->eventId) || empty($data->userId)) send_response(['message' => 'Dados insuficientes.'], 400);
    
    $validation_code = uniqid('pgeca-') . bin2hex(random_bytes(8));
    $stmt = $db->prepare("INSERT INTO certificados (id_evento, id_usuario, data_emissao, codigo_validacao) VALUES (:id_evento, :id_usuario, CURDATE(), :codigo)");
    try 
    {
        $stmt->execute([
            'id_evento' => $data->eventId,
            'id_usuario' => $data->userId,
            'codigo' => $validation_code
        ]);
        send_response(['success' => true, 'message' => 'Certificado emitido com sucesso!']);
    } 
    catch (PDOException $e) 
    {
        if ($e->getCode() == 23000) { // Trata erro de certificado duplicado.
            send_response(['message' => 'Este usuário já possui um certificado para este evento.'], 409);
        } 
        else 
        {
            send_response(['message' => 'Erro ao emitir certificado: ' . $e->getMessage()], 500);
        }
    }
}

// Retorna os dados agregados das avaliações de um evento.
function getEventReport($db, $eventId) 
{
    $stmt = $db->prepare("SELECT AVG(estrelas) as average_rating, COUNT(*) as total_ratings FROM avaliacoes WHERE id_evento = :id");
    $stmt->execute(['id' => $eventId]);
    $summary = $stmt->fetch(PDO::FETCH_ASSOC);

    $stmt = $db->prepare("SELECT estrelas, comentario FROM avaliacoes WHERE id_evento = :id AND comentario IS NOT NULL AND comentario != ''");
    $stmt->execute(['id' => $eventId]);
    $comments = $stmt->fetchAll(PDO::FETCH_ASSOC);

    send_response(['summary' => $summary, 'comments' => $comments]);
}

?>
