<?php
// Define as constantes de configuração do banco de dados
define('DB_HOST', 'localhost'); // Geralmente 'localhost'
define('DB_USER', 'root');      // Seu usuário do MySQL
define('DB_PASS', '');          // Sua senha do MySQL
define('DB_NAME', 'pgeca_db');  // O nome do banco de dados que você criou

class Database 
{

    private $conn;

    // Conecta ao banco de dados ao instanciar a classe
    public function connect() 
    {
        $this->conn = null;

        try 
        {
            // String de conexão (DSN)
            $dsn = 'mysql:host=' . DB_HOST . ';dbname=' . DB_NAME . ';charset=utf8mb4';
            
            // Cria uma instância do PDO (PHP Data Objects)
            $this->conn = new PDO($dsn, DB_USER, DB_PASS);
            
            // Define o modo de erro do PDO para exceção
            $this->conn->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
            
            // Define o modo de busca padrão para retornar arrays associativos
            $this->conn->setAttribute(PDO::ATTR_DEFAULT_FETCH_MODE, PDO::FETCH_ASSOC);
        } 
        catch(PDOException $e) 
        {
            // Em caso de erro na conexão, exibe a mensagem
            echo 'Connection Error: ' . $e->getMessage();
        }

        return $this->conn;
    }
}
?>
