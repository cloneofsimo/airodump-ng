#include <bits/stdc++.h>
#include <libnet.h>
#include <pcap.h>
using namespace std;
#pragma pack(push, 1)
struct Mac {
    uint8_t mac[6];
    Mac(uint8_t* m) {
        memcpy(mac, m, 6);
    }
    Mac() {
        memset(mac, 0, 6);
    }
    bool operator==(const Mac& m) const {
        return memcmp(mac, m.mac, 6) == 0;
    }
    bool operator<(const Mac& m) const {
        return memcmp(mac, m.mac, 6) < 0;
    }
    bool operator>(const Mac& m) const {
        return memcmp(mac, m.mac, 6) > 0;
    }
};
#pragma pack(pop)


struct Beacon {
    uint8_t type;
    uint8_t flags;
    uint16_t duration;
    Mac addr;
    Mac addr2;
    Mac bssid;
    uint16_t seq;
};


#pragma pack(push, 1)
struct RadioTap {
    uint8_t  version;
    uint8_t  pad;
    uint16_t len;
    uint32_t present;
};
#pragma pack(pop)


map<Mac, int> beacons;
map<Mac, string> essids;

void usage() {
    cout << "syntax : airodump <interface>" << endl;
    cout << "sample : airodump mon0" << endl;
}

int main(int argc, char* argv[]) {
    if (argc != 2) {
        usage();
        return -1;
    }


    char* dev = argv[1];
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
    if (handle == nullptr) {
        fprintf(stderr, "pcap_open_live(%s) return nullptr - %s\n", dev, errbuf);
        return -1;
    }
    while (true) {
        struct pcap_pkthdr* header;
        const u_char* packet;

        int res = pcap_next_ex(handle, &header, &packet);
        if (res == 0) continue;
        if (res == -1 || res == -2) {
            printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(handle));
            break;
        }

        cout << "foundpkt" << '\n';

        RadioTap* radio_tap = (RadioTap*)packet;
        Beacon* dot11_beacon = (Beacon*)(packet + radio_tap->len);
        if (dot11_beacon->type == 0x80) {

            // if beacon

            Mac addr = Mac(dot11_beacon->addr.mac);
            Mac bssid = Mac(dot11_beacon->bssid.mac);
            if (beacons.find(bssid) == beacons.end()) {
                beacons[bssid] = 0;
                string essid = "";
                const u_char* essid_c = packet + 62;
                while (*essid_c > 0x1) {
                    essid += *essid_c;
                    essid_c++;
                }
                essid += '\0';
                essids[bssid] = essid;
            }
            beacons[bssid] += 1;


            // clear console
            system("clear");

            // iterate over macs
            for (auto& it : beacons) {
                Mac mac = it.first;
                int seq = it.second;
                string essid = essids[mac];
                printf("%02x:%02x:%02x:%02x:%02x:%02x %s %d\n",
                    mac.mac[0], mac.mac[1], mac.mac[2],
                    mac.mac[3], mac.mac[4], mac.mac[5],
                    essid.c_str(), seq >> 4);
            }
        }
    }


}