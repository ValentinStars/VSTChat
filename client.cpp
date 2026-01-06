#include "common.hpp"

SOCKET sock;
std::string my_nick;
std::vector<unsigned char> session_key;
bool running = true;

void print_logo()
{
    set_color_cyan();
    std::cout << R"(
                                                 tttt
                                                ttt:::t
                                                t:::::t
                                                t:::::t
 vvvvvvv           vvvvvvv   ssssssssss   ttttttt:::::ttttttt
  v:::::v         v:::::v  ss::::::::::s  t:::::::::::::::::t
   v:::::v       v:::::v ss:::::::::::::s t:::::::::::::::::t
    v:::::v     v:::::v  s::::::ssss:::::stttttt:::::::tttttt
     v:::::v   v:::::v    s:::::s  ssssss       t:::::t
      v:::::v v:::::v        s::::::s           t:::::t
       v:::::v:::::v            s::::::s        t:::::t
        v:::::::::v       ssssss   s:::::s      t:::::t    tttttt
         v:::::::v        s:::::ssss::::::s     t::::::tttt:::::t
          v:::::v         s::::::::::::::s      tt::::::::::::::t
           v:::v           s:::::::::::ss         tt:::::::::::tt
            vvv             sssssssssss             ttttttttttt

                                           VSTChat 0.1.0 Open Beta
    )" << "\n";
    set_color_reset();
}

void loading_bar(const std::string &text)
{
    std::cout << text << " [";
    for (int i = 0; i < 20; i++)
    {
        std::cout << "=";
        std::cout.flush();
        std::this_thread::sleep_for(std::chrono::milliseconds(20));
    }
    std::cout << "] OK\n";
}

std::string recv_packet(int &out_type)
{
    uint32_t type_n, len_n;
    if (recv(sock, (char *)&type_n, 4, 0) <= 0)
        return "";
    if (recv(sock, (char *)&len_n, 4, 0) <= 0)
        return "";
    out_type = ntohl(type_n);
    int len = ntohl(len_n);
    std::vector<char> buf(len);
    int total = 0;
    while (total < len)
    {
        int r = recv(sock, buf.data() + total, len - total, 0);
        if (r <= 0)
            return "";
        total += r;
    }
    return std::string(buf.begin(), buf.end());
}

void send_packet_cli(int type, const std::string &data)
{
    uint32_t type_n = htonl(type);
    uint32_t len_n = htonl(data.size());
    send(sock, (char *)&type_n, 4, 0);
    send(sock, (char *)&len_n, 4, 0);
    if (!data.empty())
        send(sock, data.c_str(), data.size(), 0);
}

void receiver_thread()
{
    while (running)
    {
        int type;
        std::string data = recv_packet(type);
        if (data.empty())
        {
            set_color_red();
            std::cout << "\n[!] Connection lost.\n";
            set_color_reset();
            running = false;
            exit(0);
        }

        if (type == MESSAGE)
        {
            std::string clear_text = aes_gcm_decrypt(data, session_key);
            if (!clear_text.empty())
            {
                std::cout << "\r" << clear_text << "\n> " << std::flush;
            }
            else
            {
            }
        }
    }
}

int main()
{
    cls();
#ifdef _WIN32
    WSADATA wsa;
    WSAStartup(MAKEWORD(2, 2), &wsa);
#endif

    print_logo();
    std::string ip;
    std::cout << "> Enter Server IP (default 127.0.0.1): ";
    std::getline(std::cin, ip);
    if (ip.empty())
        ip = "127.0.0.1";

    sock = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in addr;
    addr.sin_family = AF_INET;
    inet_pton(AF_INET, ip.c_str(), &addr.sin_addr);
    addr.sin_port = htons(4433);

    loading_bar("Connecting to Secure Cloud");
    if (connect(sock, (struct sockaddr *)&addr, sizeof(addr)) < 0)
    {
        set_color_red();
        std::cout << "Connection Failed!\n";
        return 1;
    }

    // Handshake
    send_packet_cli(HANDSHAKE, std::to_string(PROTOCOL_VERSION));
    int type;
    std::string resp = recv_packet(type);
    if (resp != "OK_HANDSHAKE")
    {
        std::cout << "Server Error: " << resp << "\n";
        return 1;
    }

    while (true)
    {
        std::cout << "\n1. Login\n2. Register\n> ";
        std::string choice;
        std::getline(std::cin, choice);

        std::string nick, pass;
        std::cout << "Nickname: ";
        std::getline(std::cin, nick);
        std::cout << "Password: ";
        std::getline(std::cin, pass);

        unsigned char hash[SHA256_DIGEST_LENGTH];
        SHA256((unsigned char *)pass.c_str(), pass.size(), hash);
        std::stringstream ss;
        for (int i = 0; i < SHA256_DIGEST_LENGTH; i++)
            ss << std::hex << std::setw(2) << std::setfill('0') << (int)hash[i];
        std::string pass_hash = ss.str();

        if (choice == "1")
            send_packet_cli(LOGIN, nick + ":" + pass_hash);
        else
            send_packet_cli(REGISTER, nick + ":" + pass_hash);

        std::string res = recv_packet(type);
        if (res == "OK_LOGIN" || res == "OK_REGISTER")
        {
            my_nick = nick;
            set_color_green();
            std::cout << "Access Granted.\n";
            set_color_reset();
            break;
        }
        else
        {
            set_color_red();
            std::cout << "[SERVER] " << res << "\n";
            set_color_reset();
        }
    }

    loading_bar("Fetching Secure Nodes");
    send_packet_cli(GET_ROOMS, "");
    std::string rooms_raw = recv_packet(type);

    std::vector<std::pair<std::string, std::string>> room_list;
    std::stringstream ss(rooms_raw);
    std::string segment;

    std::cout << "\nAvailabe Channels:\n";
    std::vector<std::string> room_ids;
    int idx = 0;
    while (std::getline(ss, segment, ';'))
    {
        size_t d1 = segment.find(':');
        size_t d2 = segment.rfind(':');
        std::string name = segment.substr(d1 + 1, d2 - (d1 + 1));
        std::string uuid = segment.substr(d2 + 1);
        room_ids.push_back(uuid);
        std::cout << "[" << idx++ << "] " << name << "\n";
    }

    int r_choice;
    std::cout << "> Select Channel ID: ";
    std::cin >> r_choice;
    std::cin.ignore();

    std::string room_pass;
    std::cout << "> Enter CHANNEL DECRYPTION KEY: ";
    std::getline(std::cin, room_pass);

    session_key = derive_key(room_pass, room_ids[r_choice]);

    send_packet_cli(JOIN_ROOM, std::to_string(r_choice));

    cls();
    print_logo();
    std::cout << "Encrypted Channel Established using AES-256-GCM\n";
    std::cout << "Identity: " << my_nick << "\n";
    std::cout << "-----------------------------------------------\n";

    std::thread(receiver_thread).detach();

    while (running)
    {
        std::string msg;
        std::cout << "> ";
        std::getline(std::cin, msg);
        if (msg == "/exit")
            break;
        if (msg.empty())
            continue;

        time_t now = time(0);
        tm *ltm = localtime(&now);
        std::stringstream time_ss;
        time_ss << "[" << std::setw(2) << std::setfill('0') << ltm->tm_hour << ":" << std::setw(2) << ltm->tm_min << "]";

        std::string full_msg = time_ss.str() + " " + my_nick + ": " + msg;

        std::string enc = aes_gcm_encrypt(full_msg, session_key);
        send_packet_cli(MESSAGE, enc);
    }

    return 0;
}