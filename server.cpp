// VSTChat server.cpp open beta

#include "common.hpp"
#include <fstream>
#include <map>
#include <thread>
#include <mutex>
#include <atomic>
#include <filesystem>
#include <algorithm>

#ifdef _WIN32
#include <winsock2.h>
#pragma comment(lib, "ws2_32.lib")
#else
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#define SOCKET int
#define INVALID_SOCKET -1
#endif

namespace fs = std::filesystem;

bool USE_WHITELIST = false;
bool ENABLE_LOGS = true;

struct UserData
{
    std::string password_hash;
    std::string salt;
};

struct Room
{
    std::string id;
    std::string name;
    std::vector<SOCKET> clients;
};

std::map<std::string, UserData> database; // Nick это Data
std::vector<std::string> whitelist;       // Nicknames
std::vector<Room> rooms;
std::mutex db_mutex;

void log_server(const std::string &msg)
{
    if (!ENABLE_LOGS)
        return;
    std::lock_guard<std::mutex> lock(db_mutex);
    std::cout << "[LOG] " << msg << "\n";
    std::ofstream logfile("server.log", std::ios::app);
    logfile << msg << "\n";
}

void load_db()
{
    if (!fs::exists("users.db"))
        return;
    std::ifstream file("users.db");
    std::string line;
    while (std::getline(file, line))
    {
        std::stringstream ss(line);
        std::string nick, pass, salt;
        std::getline(ss, nick, ':');
        std::getline(ss, pass, ':');
        std::getline(ss, salt, ':');
        database[nick] = {pass, salt};
    }
    log_server("Database loaded. Users: " + std::to_string(database.size()));
}

void save_user(const std::string &nick, const std::string &pass_hash, const std::string &salt)
{
    std::lock_guard<std::mutex> lock(db_mutex);
    database[nick] = {pass_hash, salt};
    std::ofstream file("users.db", std::ios::app);
    file << nick << ":" << pass_hash << ":" << salt << "\n";
}

void load_whitelist()
{
    if (!fs::exists("whitelist.db"))
        return;
    std::ifstream file("whitelist.db");
    std::string nick;
    while (std::getline(file, nick))
    {
        whitelist.push_back(nick);
    }
}

bool is_whitelisted(const std::string &nick)
{
    if (!USE_WHITELIST)
        return true;
    for (const auto &w : whitelist)
        if (w == nick)
            return true;
    return false;
}

void add_to_whitelist(const std::string &nick)
{
    std::lock_guard<std::mutex> lock(db_mutex);
    whitelist.push_back(nick);
    std::ofstream file("whitelist.db", std::ios::app);
    file << nick << "\n";
    log_server("User added to whitelist: " + nick);
}

void send_packet(SOCKET sock, int type, const std::string &data)
{
    uint32_t type_n = htonl(type);
    uint32_t len_n = htonl(data.size());
    send(sock, (char *)&type_n, 4, 0);
    send(sock, (char *)&len_n, 4, 0);
    if (!data.empty())
        send(sock, data.c_str(), data.size(), 0);
}

void client_handler(SOCKET sock)
{
    std::string username = "";
    int current_room_idx = -1;
    bool authed = false;

    while (true)
    {
        uint32_t type_n, len_n;
        if (recv(sock, (char *)&type_n, 4, 0) <= 0)
            break;
        if (recv(sock, (char *)&len_n, 4, 0) <= 0)
            break;

        int type = ntohl(type_n);
        int len = ntohl(len_n);
        std::vector<char> buf(len);
        if (len > 0)
            recv(sock, buf.data(), len, 0);
        std::string payload(buf.begin(), buf.end());

        if (type == HANDSHAKE)
        {
            int ver = std::stoi(payload);
            if (ver != PROTOCOL_VERSION)
            {
                send_packet(sock, SERVER_RESPONSE, "ERROR: Client version mismatch. Update client.");
                break;
            }
            send_packet(sock, SERVER_RESPONSE, "OK_HANDSHAKE");
        }
        else if (type == LOGIN)
        {
            size_t del = payload.find(':');
            std::string nick = payload.substr(0, del);
            std::string pass_hash = payload.substr(del + 1);

            if (!is_whitelisted(nick))
            {
                send_packet(sock, SERVER_RESPONSE, "ERROR: Whitelist enabled. Ask admin to approve: " + nick);
                continue;
            }

            if (database.find(nick) != database.end())
            {
                if (database[nick].password_hash == pass_hash)
                {
                    username = nick;
                    authed = true;
                    send_packet(sock, SERVER_RESPONSE, "OK_LOGIN");
                    log_server(nick + " logged in.");
                }
                else
                {
                    send_packet(sock, SERVER_RESPONSE, "ERROR: Wrong password.");
                }
            }
            else
            {
                send_packet(sock, SERVER_RESPONSE, "ERROR: User not found.");
            }
        }
        else if (type == REGISTER)
        {
            size_t del = payload.find(':');
            std::string nick = payload.substr(0, del);
            std::string pass_hash = payload.substr(del + 1);

            if (!is_whitelisted(nick))
            {
                log_server("WL Request from: " + nick);
                send_packet(sock, SERVER_RESPONSE, "WAIT: Account pending approval by Admin.");
            }
            else if (database.find(nick) != database.end())
            {
                send_packet(sock, SERVER_RESPONSE, "ERROR: Nickname taken.");
            }
            else
            {
                save_user(nick, pass_hash, "static_salt_v1");
                username = nick;
                authed = true;
                send_packet(sock, SERVER_RESPONSE, "OK_REGISTER");
                log_server("New user registered: " + nick);
            }
        }
        else if (authed)
        {
            if (type == GET_ROOMS)
            {
                std::stringstream ss;
                for (size_t i = 0; i < rooms.size(); i++)
                {
                    ss << i << ":" << rooms[i].name << ":" << rooms[i].id << ";";
                }
                send_packet(sock, SEND_ROOMS, ss.str());
            }
            else if (type == JOIN_ROOM)
            {
                int idx = std::stoi(payload);
                if (idx >= 0 && idx < rooms.size())
                {
                    std::lock_guard<std::mutex> lock(db_mutex);
                    current_room_idx = idx;
                    rooms[idx].clients.push_back(sock);
                    log_server(username + " joined room " + rooms[idx].name);
                }
            }
            else if (type == MESSAGE)
            {
                if (current_room_idx != -1)
                {
                    std::lock_guard<std::mutex> lock(db_mutex);
                    for (SOCKET s : rooms[current_room_idx].clients)
                    {
                        if (s != sock)
                            send_packet(s, MESSAGE, payload);
                    }
                }
            }
        }
    }

#ifdef _WIN32
    closesocket(sock);
#else
    close(sock);
#endif
    if (current_room_idx != -1)
    {
        std::lock_guard<std::mutex> lock(db_mutex);
        auto &c = rooms[current_room_idx].clients;
        c.erase(std::remove(c.begin(), c.end(), sock), c.end());
    }
    log_server("Client disconnected.");
}

void admin_console()
{
    std::string cmd;
    while (true)
    {
        std::getline(std::cin, cmd);
        if (cmd == "/whitelist on")
        {
            USE_WHITELIST = true;
            log_server("Whitelist ENABLED");
        }
        else if (cmd == "/whitelist off")
        {
            USE_WHITELIST = false;
            log_server("Whitelist DISABLED");
        }
        else if (cmd.rfind("/approve ", 0) == 0)
        {
            std::string nick = cmd.substr(9);
            add_to_whitelist(nick);
            std::cout << "User " << nick << " approved!\n";
        }
        else if (cmd == "/users")
        {
            std::cout << "Registered users: " << database.size() << "\n";
        }
    }
}

int main()
{
    cls();
    load_db();
    load_whitelist();

    rooms.push_back({"room_uuid_gen_1", "General", {}});
    rooms.push_back({"room_uuid_game_2", "Gaming", {}});
    rooms.push_back({"room_uuid_dev_3", "DevOps", {}});
    rooms.push_back({"room_uuid_vip_4", "VIP Lounge", {}});

    set_color_cyan();
    std::cout << "VSTChat SERVER [PREMIUM CORE]\n";
    std::cout << "Listening on port 4433...\n";
    set_color_reset();

#ifdef _WIN32
    WSADATA wsa;
    WSAStartup(MAKEWORD(2, 2), &wsa);
#endif

    SOCKET server_fd = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in addr;
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = INADDR_ANY;
    addr.sin_port = htons(4433);

    bind(server_fd, (struct sockaddr *)&addr, sizeof(addr));
    listen(server_fd, 10);

    std::thread(admin_console).detach();

    while (true)
    {
        SOCKET client = accept(server_fd, NULL, NULL);
        if (client != INVALID_SOCKET)
        {
            std::thread(client_handler, client).detach();
        }
    }
}
