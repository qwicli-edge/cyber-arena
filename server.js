const express = require('express');
const http = require('http');
const socketIo = require('socket.io');
const cors = require('cors');
const path = require('path');

const app = express();
const server = http.createServer(app);
const io = socketIo(server, {
    cors: { origin: "*", methods: ["GET", "POST"] }
});

app.use(cors());
app.use(express.static('public'));

// ========== ТРИ БАЗЫ ВОПРОСОВ ==========

// 1. Базовый тест ИБ (10 вопросов)
const BASIC_QUESTIONS = [
    { text: "Вы отошли от ноутбука на 5 минут в коворкинге. Что нужно сделать?", options: ["Ничего, вокруг свои люди", "Закрыть крышку/блокировка Win+L", "Выключить роутер", "Спрятать ноутбук"], correct: 1, explanation: "Блокировка экрана предотвращает доступ к данным за секунды." },
    { text: "Получили письмо от 'службы поддержки' с просьбой подтвердить пароль. Ваши действия?", options: ["Перейти по ссылке", "Сообщить в IT-отдел", "Ответить на письмо", "Позвонить в Google"], correct: 1, explanation: "Фишинг. Не переходите по ссылкам." },
    { text: "Нашли USB-флешку на парковке. Что делать?", options: ["Воткнуть в ПК", "Отдать службе безопасности", "Выкинуть", "Вставить дома"], correct: 1, explanation: "Флешка может содержать вредоносное ПО." },
    { text: "Коллега просит дать свой пропуск. Ваше решение?", options: ["Дать пропуск", "Отправить к администратору", "Дать с распиской", "Сообщить начальнику"], correct: 1, explanation: "Передача пропуска нарушает политику безопасности." },
    { text: "Компьютер стал медленным, антивирус отключён. Что делать?", options: ["Перезагрузить", "Отключить от сети и сообщить в IT", "Скачать антивирус", "Продолжить"], correct: 1, explanation: "Признаки заражения." },
    { text: "Звонит 'сотрудник IT', просит скачать программу. Ваши действия?", options: ["Скачать", "Перезвонить в IT", "Отправить ссылку коллеге", "Запустить с антивирусом"], correct: 1, explanation: "Социальная инженерия." },
    { text: "Что повышает безопасность Wi-Fi дома?", options: ["Оставить SSID по умолчанию", "WPA3/WPA2 + сложный пароль", "Отключить брандмауэр", "Включить WPS"], correct: 1, explanation: "Шифрование и сложный пароль — основа." },
    { text: "SMS о блокировке карты. Что делать?", options: ["Перейти по ссылке", "Позвонить в банк", "Ответить", "Переслать"], correct: 1, explanation: "Смишинг. Звоните в банк." },
    { text: "Один пароль для нескольких сервисов — это?", options: ["Нормально", "Опасно", "Безопасно с 2FA", "Разрешено"], correct: 1, explanation: "Утечка одного = доступ ко всем." },
    { text: "Нашли листок с паролем коллеги. Что делать?", options: ["Сфотографировать", "Убрать в стол", "Сообщить коллеге и уничтожить", "Использовать"], correct: 2, explanation: "Нарушение политики безопасности." }
];

// 2. Администраторский тест (10 вопросов)
const ADMIN_QUESTIONS = [
    { text: "В auth.log: множество Failed password для root, затем Accepted. Первое действие?", options: ["Увеличить сложность пароля", "Заблокировать IP через firewall", "Сменить пароль root", "Отключить SSH по паролю"], correct: 1, explanation: "Блокировка атакующего IP останавливает атаку." },
    { text: "Какой Event ID Windows указывает на успешный вход?", options: ["4624", "4625", "4648", "4720"], correct: 0, explanation: "4624 — успешный вход." },
    { text: "Сервер устанавливает исходящие соединения на порт 4444. Что делать?", options: ["Заблокировать порт", "Отключить сервер", "Запустить tcpdump", "Сбросить iptables"], correct: [0,1], explanation: "Блокировка порта и отключение сервера." },
    { text: "В логах: GET /page.php?id=1 UNION SELECT... Тип атаки?", options: ["SQL-инъекция", "XSS", "Path traversal", "CSRF"], correct: 0, explanation: "Типичная SQL-инъекция." },
    { text: "Как найти последние входы админа на всех DC?", options: ["Get-ADUser", "Get-WinEvent с ID 4624", "whoami /groups", "net user"], correct: 1, explanation: "Get-WinEvent собирает события 4624." },
    { text: "Условия восстановления после ransomware?", options: ["Теневые копии", "Изолированные бэкапы", "Антивирус удалил", "Immutable storage"], correct: [1,3], explanation: "Изолированность и неизменяемость бэкапов." },
    { text: "Подозрительный процесс на порту 31337. Что делать?", options: ["kill -9", "strace -p", "cat /proc/pid/maps и lsof", "systemctl stop"], correct: 2, explanation: "Просмотр карт памяти без остановки." },
    { text: "ARP-пакеты с подменой MAC — это?", options: ["ARP spoofing", "MAC flooding", "DNS spoofing", "DHCP starvation"], correct: 0, explanation: "ARP spoofing. Защита — DAI." },
    { text: "Logon Type 10, затем изменения в AD. Атака?", options: ["Pass-the-hash", "Pass-the-ticket", "Легитимный админ", "RDP + PsExec"], correct: 3, explanation: "RDP + PsExec для AD." },
    { text: "Reply-To: fake@gmail.com в письме. Это?", options: ["SPF-подделка", "Mail bombing", "Reply-to spoofing", "SMTP relay"], correct: 2, explanation: "Подмена адреса для ответа." }
];

// 3. Форензика + Инциденты (8 вопросов)
const FORENSICS_QUESTIONS = [
    { text: "history: cat /etc/shadow, rm -rf /var/log/auth.log. Что скрывает?", options: ["Логи аутентификации", "Домашнюю папку", "Кэш браузера", "Временные файлы"], correct: 0, explanation: "Удаляет логи auth.log." },
    { text: "Event 4624, Logon Type 10, Process: svchost.exe. Что необычно?", options: ["Logon Type", "Source IP", "Process Name", "Package"], correct: 2, explanation: "svchost.exe не инициирует вход." },
    { text: "Лог nginx: ?cmd=cat+/etc/passwd → 200, 2456 байт. Что значит 200?", options: ["Ошибка", "Успешный ответ", "Редирект", "Доступ запрещён"], correct: 1, explanation: "Код 200 + большой объём данных." },
    { text: "ps aux: /tmp/.rsync --pool=1 --cpu=2. Что это?", options: ["Легитимный rsync", "Майнер", "Системный процесс", "Бэкдор"], correct: 1, explanation: "Скрытый путь и аргументы майнера." },
    { text: "Run → C:\\Users\\Public\\svchost.exe. Почему подозрительно?", options: ["Нестандартный путь", "Имя процесса", "Ключ реестра", "Нет параметров"], correct: 0, explanation: "Настоящий svchost.exe в System32." },
    { text: "Как обнаружить сетевые соединения процесса Linux?", options: ["ls -la", "lsof -p PID", "cat /etc/passwd", "systemctl status"], correct: 1, explanation: "lsof -p показывает открытые сокеты." },
    { text: "Ransomware уничтожил теневые копии. Что гарантирует восстановление?", options: ["Обновление антивируса", "Изолированные immutable-бэкапы", "Переустановка ОС", "Отключение интернета"], correct: 1, explanation: "Только изолированные неизменяемые бэкапы." },
    { text: "Подозрительный DNS-запрос. Первое действие?", options: ["Заблокировать домен", "Проанализировать трафик", "Перезагрузить сервер", "Сменить пароли"], correct: 1, explanation: "Сначала анализ для понимания масштаба." }
];

// Глобальное хранилище
let rooms = {};
let users = {};
let globalStats = {};

function getRandomQuestions(mode, count = 7) {
    let source;
    if (mode === 'basic') source = [...BASIC_QUESTIONS];
    else if (mode === 'admin') source = [...ADMIN_QUESTIONS];
    else source = [...FORENSICS_QUESTIONS];
    
    for (let i = source.length - 1; i > 0; i--) {
        const j = Math.floor(Math.random() * (i + 1));
        [source[i], source[j]] = [source[j], source[i]];
    }
    return source.slice(0, Math.min(count, source.length));
}

function getRoomsList() {
    const list = [];
    for (let id in rooms) {
        const r = rooms[id];
        if (!r.gameStarted) {
            list.push({ id: r.id, name: r.name, players: r.players.length, maxPlayers: r.maxPlayers, owner: r.ownerName, mode: r.mode });
        }
    }
    return list;
}

function getLeaderboard() {
    const stats = [];
    for (let name in globalStats) {
        stats.push({ name: name, totalScore: globalStats[name].score, gamesPlayed: globalStats[name].games });
    }
    stats.sort((a, b) => b.totalScore - a.totalScore);
    return stats.slice(0, 10);
}

io.on('connection', (socket) => {
    console.log('🔌 Игрок подключился:', socket.id);
    users[socket.id] = { id: socket.id, name: null, roomId: null, score: 0 };
    
    socket.on('getRooms', () => socket.emit('roomsList', getRoomsList()));
    socket.on('getLeaderboard', () => socket.emit('leaderboardUpdate', getLeaderboard()));
    
    socket.on('createRoom', ({ roomName, playerName, mode }, callback) => {
        const roomId = Date.now().toString() + Math.random().toString(36).substr(2, 4);
        rooms[roomId] = {
            id: roomId, name: roomName, mode: mode,
            players: [{ id: socket.id, name: playerName, score: 0, answered: false }],
            maxPlayers: 4, gameStarted: false, questions: [], currentQuestion: 0,
            ownerId: socket.id, ownerName: playerName
        };
        users[socket.id].name = playerName;
        users[socket.id].roomId = roomId;
        socket.join(roomId);
        callback({ success: true, roomId, room: rooms[roomId] });
        io.emit('roomsList', getRoomsList());
    });
    
    socket.on('joinRoom', ({ roomId, playerName }, callback) => {
        const room = rooms[roomId];
        if (!room) return callback({ success: false, error: 'Комната не найдена' });
        if (room.gameStarted) return callback({ success: false, error: 'Игра уже началась' });
        if (room.players.length >= room.maxPlayers) return callback({ success: false, error: 'Комната полна' });
        if (room.players.find(p => p.name === playerName)) return callback({ success: false, error: 'Имя уже занято' });
        
        room.players.push({ id: socket.id, name: playerName, score: 0, answered: false });
        users[socket.id].name = playerName;
        users[socket.id].roomId = roomId;
        socket.join(roomId);
        callback({ success: true, room });
        io.to(roomId).emit('roomUpdate', room);
        io.emit('roomsList', getRoomsList());
    });
    
    socket.on('startGame', ({ roomId }) => {
        const room = rooms[roomId];
        if (!room || room.ownerId !== socket.id) return;
        room.questions = getRandomQuestions(room.mode, 7);
        room.gameStarted = true;
        room.currentQuestion = 0;
        room.players.forEach(p => { p.score = 0; p.answered = false; });
        io.to(roomId).emit('gameStarted', { 
            question: room.questions[0], questionIndex: 0, totalQuestions: room.questions.length,
            players: room.players, mode: room.mode
        });
    });
    
    socket.on('submitAnswer', ({ roomId, answerIndex }) => {
        const room = rooms[roomId];
        if (!room || !room.gameStarted) return;
        const player = room.players.find(p => p.id === socket.id);
        if (!player || player.answered) return;
        const currentQ = room.questions[room.currentQuestion];
        const isCorrect = (answerIndex === currentQ.correct);
        if (isCorrect) player.score += 10;
        player.answered = true;
        io.to(roomId).emit('answerResult', {
            playerId: socket.id, playerName: player.name, score: player.score,
            isCorrect, explanation: currentQ.explanation,
            correctAnswer: currentQ.correct, options: currentQ.options
        });
        const allAnswered = room.players.every(p => p.answered);
        if (allAnswered) {
            if (room.currentQuestion + 1 >= room.questions.length) {
                const sorted = [...room.players].sort((a, b) => b.score - a.score);
                const winner = sorted[0];
                room.players.forEach(p => {
                    if (!globalStats[p.name]) globalStats[p.name] = { score: 0, games: 0 };
                    globalStats[p.name].score += p.score;
                    globalStats[p.name].games += 1;
                });
                io.to(roomId).emit('gameFinished', { players: room.players, winner: winner.name, finalScores: room.players.map(p => ({ name: p.name, score: p.score })) });
                delete rooms[roomId];
                io.emit('roomsList', getRoomsList());
                io.emit('leaderboardUpdate', getLeaderboard());
            } else {
                room.currentQuestion++;
                room.players.forEach(p => p.answered = false);
                io.to(roomId).emit('nextQuestion', { question: room.questions[room.currentQuestion], questionIndex: room.currentQuestion, totalQuestions: room.questions.length, players: room.players });
            }
        }
    });
    
    socket.on('leaveRoom', () => {
        const user = users[socket.id];
        if (user && user.roomId) {
            const room = rooms[user.roomId];
            if (room) {
                room.players = room.players.filter(p => p.id !== socket.id);
                if (room.players.length === 0) delete rooms[user.roomId];
                else if (room.ownerId === socket.id) { room.ownerId = room.players[0].id; room.ownerName = room.players[0].name; }
                io.emit('roomsList', getRoomsList());
                if (rooms[user.roomId]) io.to(user.roomId).emit('roomUpdate', rooms[user.roomId]);
            }
            socket.leave(user.roomId);
            user.roomId = null;
        }
    });
    
    socket.on('disconnect', () => {
        const user = users[socket.id];
        if (user && user.roomId) {
            const room = rooms[user.roomId];
            if (room) {
                room.players = room.players.filter(p => p.id !== socket.id);
                if (room.players.length === 0) delete rooms[user.roomId];
                else if (room.ownerId === socket.id) { room.ownerId = room.players[0].id; room.ownerName = room.players[0].name; }
                io.emit('roomsList', getRoomsList());
                if (rooms[user.roomId]) io.to(user.roomId).emit('roomUpdate', rooms[user.roomId]);
            }
        }
        delete users[socket.id];
    });
});

app.get('/', (req, res) => res.sendFile(path.join(__dirname, 'public', 'index.html')));
const PORT = process.env.PORT || 3000;
server.listen(PORT, () => console.log(`✅ Сервер на http://localhost:${PORT}`));