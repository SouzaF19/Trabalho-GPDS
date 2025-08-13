
-- Tabela para armazenar os usuarios (participantes e organizadores)
CREATE TABLE `usuarios` (
  `id`      INT AUTO_INCREMENT  PRIMARY KEY,
  `nome`    VARCHAR(200)        NOT NULL,
  `email`   VARCHAR(150)        NOT NULL UNIQUE,
  `senha`   VARCHAR(250)        NOT NULL, -- Armazene senhas com hash (ex: password_hash() do PHP)
  `tipo` ENUM('PARTICIPANTE', 'ORGANIZADOR') NOT NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- Tabela para armazenar os eventos
CREATE TABLE `eventos` (
  `id`                    INT AUTO_INCREMENT      PRIMARY KEY,
  `id_organizador`        INT                     NOT NULL,
  `nome`                  VARCHAR(200)            NOT NULL,
  `data`                  DATE                    NOT NULL,
  `local`                 VARCHAR(200)            NOT NULL,
  `palestrante`           VARCHAR(200)            DEFAULT NULL,
  `carga_horaria`         INT                     DEFAULT NULL,
  `is_online`             BOOLEAN                 NOT NULL DEFAULT FALSE,
  `status`                ENUM('open', 'closed')  NOT NULL DEFAULT 'open',
  `descricao`             TEXT,
  `imagem_url`            VARCHAR(2048)           DEFAULT NULL,
  `permite_submissao`     BOOLEAN                 NOT NULL DEFAULT FALSE,
  `info_revisor_formacao` VARCHAR(250)            DEFAULT NULL,
  FOREIGN KEY (`id_organizador`) REFERENCES `usuarios`(`id`) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- Tabela para a programação de cada evento (relação 1-N com eventos)
CREATE TABLE `programacao` (
  `id`        INT AUTO_INCREMENT  PRIMARY KEY,
  `id_evento` INT                 NOT NULL,
  `horario`   TIME                NOT NULL,
  `titulo`    VARCHAR(200)        NOT NULL,
  FOREIGN KEY (`id_evento`) REFERENCES `eventos`(`id`) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- Tabela de associaçao para inscriçoes (relação N-N entre usuários e eventos)
CREATE TABLE `inscricoes` (
  `id_usuario`  INT     NOT NULL,
  `id_evento`   INT     NOT NULL,
  PRIMARY KEY (`id_usuario`, `id_evento`),
  FOREIGN KEY (`id_usuario`) REFERENCES `usuarios`(`id`) ON DELETE CASCADE,
  FOREIGN KEY (`id_evento`) REFERENCES `eventos`(`id`) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- Tabela para os trabalhos submetidos pelos participantes
CREATE TABLE `trabalhos` (
  `id`            INT AUTO_INCREMENT  PRIMARY KEY,
  `id_evento`     INT                 NOT NULL,
  `id_usuario`    INT                 NOT NULL,
  `titulo`        VARCHAR(200)        NOT NULL,
  `autores`       TEXT                NOT NULL,
  `resumo`        TEXT                NOT NULL,
  `nome_arquivo`  VARCHAR(200)        DEFAULT NULL,
  `nota`          DECIMAL(4, 2)       DEFAULT NULL,
  `observacoes`   TEXT,
  FOREIGN KEY (`id_evento`) REFERENCES `eventos`(`id`) ON DELETE CASCADE,
  FOREIGN KEY (`id_usuario`) REFERENCES `usuarios`(`id`) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- Tabela para os certificados gerados
CREATE TABLE `certificados` (
  `id`                INT AUTO_INCREMENT  PRIMARY KEY,
  `id_evento`         INT                 NOT NULL,
  `id_usuario`        INT                 NOT NULL,
  `data_emissao`      DATE                NOT NULL,
  `codigo_validacao`  VARCHAR(250)        NOT NULL UNIQUE,
  FOREIGN KEY (`id_evento`) REFERENCES `eventos`(`id`) ON DELETE CASCADE,
  FOREIGN KEY (`id_usuario`) REFERENCES `usuarios`(`id`) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- Tabela para as avaliações dos eventos feitas pelos participantes
CREATE TABLE `avaliacoes` (
  `id`          INT AUTO_INCREMENT  PRIMARY KEY,
  `id_evento`   INT                 NOT NULL,
  `id_usuario`  INT                 NOT NULL,
  `estrelas`    INT                 NOT NULL,
  `comentario`  TEXT,
  FOREIGN KEY (`id_evento`) REFERENCES `eventos`(`id`) ON DELETE CASCADE,
  FOREIGN KEY (`id_usuario`) REFERENCES `usuarios`(`id`) ON DELETE CASCADE,
  UNIQUE KEY `unique_evaluation` (`id_evento`, `id_usuario`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- Inserindo dados de exemplo para teste
INSERT INTO `usuarios` (`id`, `nome`, `email`, `senha`, `tipo`) VALUES
(1, 'Organizador Master', 'org@pgeca.com', '$2y$10$tD.4v3j9v/jA7M2q2E9N2uG/c3G.K2p8H.oY.l5K2q.s3o4E.l5K2', 'ORGANIZADOR');

INSERT INTO `eventos` (`id`, `id_organizador`, `nome`, `data`, `local`, `palestrante`, `carga_horaria`, `is_online`, `status`, `descricao`, `imagem_url`, `permite_submissao`, `info_revisor_formacao`) VALUES
(1, 1, 'SIC - 2025', '2025-08-16', 'UEMS - Bloco G', 'Dr. Jéssica Bassani de Oliveira', 8, 0, 'open', 'Um evento que reúne os maiores especialistas em tecnologia.', 'https://placehold.co/600x400/820AD1/ffffff?text=Inovação', 1, 'Doutora em Ciência da Computação');

INSERT INTO `programacao` (`id_evento`, `horario`, `titulo`) VALUES
(1, '09:00:00', 'Abertura e Keynote'),
(1, '10:30:00', 'Palestra: O Futuro do Desenvolvimento Web'),
(1, '12:00:00', 'Almoço e Networking'),
(1, '14:00:00', 'Workshop: Engenharia de Software');
