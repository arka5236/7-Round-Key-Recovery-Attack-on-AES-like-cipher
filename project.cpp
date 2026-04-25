#include <iostream>
#include <vector>
#include <array>
#include <random>
#include <cstdint>
#include <algorithm>
#include <list>

using namespace std;

// ================= DATA STRUCTURES =================
using Vector8 = array<uint8_t, 8>;

struct Quartet_Record {
    vector<vector<uint8_t>> C0, C1, C2, C3;
};

// ================= AES CONSTANTS =================
const unsigned char s_box[16][16] = {
    {0x63, 0x7C, 0x77, 0x7B, 0xF2, 0x6B, 0x6F, 0xC5, 0x30, 0x01, 0x67, 0x2B, 0xFE, 0xD7, 0xAB, 0x76},
    {0xCA, 0x82, 0xC9, 0x7D, 0xFA, 0x59, 0x47, 0xF0, 0xAD, 0xD4, 0xA2, 0xAF, 0x9C, 0xA4, 0x72, 0xC0},
    {0xB7, 0xFD, 0x93, 0x26, 0x36, 0x3F, 0xF7, 0xCC, 0x34, 0xA5, 0xE5, 0xF1, 0x71, 0xD8, 0x31, 0x15},
    {0x04, 0xC7, 0x23, 0xC3, 0x18, 0x96, 0x05, 0x9A, 0x07, 0x12, 0x80, 0xE2, 0xEB, 0x27, 0xB2, 0x75},
    {0x09, 0x83, 0x2C, 0x1A, 0x1B, 0x6E, 0x5A, 0xA0, 0x52, 0x3B, 0xD6, 0xB3, 0x29, 0xE3, 0x2F, 0x84},
    {0x53, 0xD1, 0x00, 0xED, 0x20, 0xFC, 0xB1, 0x5B, 0x6A, 0xCB, 0xBE, 0x39, 0x4A, 0x4C, 0x58, 0xCF},
    {0xD0, 0xEF, 0xAA, 0xFB, 0x43, 0x4D, 0x33, 0x85, 0x45, 0xF9, 0x02, 0x7F, 0x50, 0x3C, 0x9F, 0xA8},
    {0x51, 0xA3, 0x40, 0x8F, 0x92, 0x9D, 0x38, 0xF5, 0xBC, 0xB6, 0xDA, 0x21, 0x10, 0xFF, 0xF3, 0xD2},
    {0xCD, 0x0C, 0x13, 0xEC, 0x5F, 0x97, 0x44, 0x17, 0xC4, 0xA7, 0x7E, 0x3D, 0x64, 0x5D, 0x19, 0x73},
    {0x60, 0x81, 0x4F, 0xDC, 0x22, 0x2A, 0x90, 0x88, 0x46, 0xEE, 0xB8, 0x14, 0xDE, 0x5E, 0x0B, 0xDB},
    {0xE0, 0x32, 0x3A, 0x0A, 0x49, 0x06, 0x24, 0x5C, 0xC2, 0xD3, 0xAC, 0x62, 0x91, 0x95, 0xE4, 0x79},
    {0xE7, 0xC8, 0x37, 0x6D, 0x8D, 0xD5, 0x4E, 0xA9, 0x6C, 0x56, 0xF4, 0xEA, 0x65, 0x7A, 0xAE, 0x08},
    {0xBA, 0x78, 0x25, 0x2E, 0x1C, 0xA6, 0xB4, 0xC6, 0xE8, 0xDD, 0x74, 0x1F, 0x4B, 0xBD, 0x8B, 0x8A},
    {0x70, 0x3E, 0xB5, 0x66, 0x48, 0x03, 0xF6, 0x0E, 0x61, 0x35, 0x57, 0xB9, 0x86, 0xC1, 0x1D, 0x9E},
    {0xE1, 0xF8, 0x98, 0x11, 0x69, 0xD9, 0x8E, 0x94, 0x9B, 0x1E, 0x87, 0xE9, 0xCE, 0x55, 0x28, 0xDF},
    {0x8C, 0xA1, 0x89, 0x0D, 0xBF, 0xE6, 0x42, 0x68, 0x41, 0x99, 0x2D, 0x0F, 0xB0, 0x54, 0xBB, 0x16}
};

const unsigned int inv_s_box[16][16] = {
    {0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb},
    {0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87, 0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb},
    {0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e},
    {0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2, 0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25},
    {0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92},
    {0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda, 0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84},
    {0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3, 0x45, 0x06},
    {0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02, 0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b},
    {0x3a, 0x91, 0x11, 0x41, 0x4f, 0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73},
    {0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 0xe2, 0xf9, 0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e},
    {0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89, 0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b},
    {0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2, 0x79, 0x20, 0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4},
    {0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f},
    {0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d, 0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef},
    {0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0, 0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61},
    {0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d}
};
const uint8_t RCon[10] = {0x01,0x02,0x04,0x08,0x10,0x20,0x40,0x80,0x1b,0x36};

// ================= HELPERS =================
uint8_t getRandomHex(mt19937& gen){
    uniform_int_distribution<> d(0,255);
    return d(gen);
}

uint8_t inverseSBox(uint8_t v){
    return inv_s_box[v>>4][v&0xF];
}

uint8_t getByteColMajor(const vector<vector<uint8_t>>& matrix, int i) {
    return matrix[i % 4][i / 4];
}

vector<vector<uint8_t>> matrixXor(const vector<vector<uint8_t>>& A,const vector<vector<uint8_t>>& B){
    vector<vector<uint8_t>> R(4,vector<uint8_t>(4));
    for(int i=0;i<4;i++) for(int j=0;j<4;j++) R[i][j]=A[i][j]^B[i][j];
    return R;
}

bool matricesEqual(const vector<vector<uint8_t>>& A,const vector<vector<uint8_t>>& B){
    for(int i=0;i<4;i++) for(int j=0;j<4;j++) if(A[i][j]!=B[i][j]) return false;
    return true;
}

int countActiveColumns(const vector<vector<uint8_t>>& matrix) {
    int active_cols = 0;
    for (int col = 0; col < 4; col++) {
        for (int row = 0; row < 4; row++) {
            if (matrix[row][col] != 0) {
                active_cols++;
                break;
            }
        }
    }
    return active_cols;
}

int countActiveBytes(const vector<vector<uint8_t>>& matrix) {
    int active = 0;
    for (auto& r : matrix)
        for (auto v : r)
            if (v) active++;
    return active;
}

int countActiveFirstTwoDiagonals(const vector<vector<uint8_t>>& s) {
    int a = 0;
    if (s[0][0]) a++; if (s[1][1]) a++;
    if (s[2][2]) a++; if (s[3][3]) a++;
    if (s[0][2]) a++; if (s[1][3]) a++;
    if (s[2][0]) a++; if (s[3][1]) a++;
    return a;
}

void build_combinations(const vector<vector<uint8_t>>& candidates, int depth, vector<uint8_t>& current, vector<vector<uint8_t>>& all_combinations) {
    if (depth == 8) {
        all_combinations.push_back(current);
        return;
    }
    for (uint8_t val : candidates[depth]) {
        current[depth] = val;
        build_combinations(candidates, depth + 1, current, all_combinations);
    }
}

// ================= AES CORE =================
void apply_s_box(vector<vector<uint8_t>>& s){
    for(auto& r:s) for(auto& v:r) v=s_box[v>>4][v&0xF];
}

void InvSubBytes(vector<vector<uint8_t>>& s){
    for(auto& r:s) for(auto& v:r) v=inverseSBox(v);
}

void shiftRows(vector<vector<uint8_t>>& s){
    rotate(s[1].begin(),s[1].begin()+1,s[1].end());
    rotate(s[2].begin(),s[2].begin()+2,s[2].end());
    rotate(s[3].begin(),s[3].begin()+3,s[3].end());
}

void InvShiftRows(vector<vector<uint8_t>>& s){
    rotate(s[1].rbegin(),s[1].rbegin()+1,s[1].rend());
    rotate(s[2].rbegin(),s[2].rbegin()+2,s[2].rend());
    rotate(s[3].rbegin(),s[3].rbegin()+3,s[3].rend());
}

uint8_t gmul(uint8_t a,uint8_t b){
    uint8_t p=0;
    for(int i=0;i<8;i++){
        if(b&1) p^=a;
        bool hi=a&0x80;
        a<<=1;
        if(hi) a^=0x1b;
        b>>=1;
    }
    return p;
}

void mixColumns(vector<vector<uint8_t>>& s){
    for(int c=0;c<4;c++){
        uint8_t t[4];
        t[0]=gmul(2,s[0][c])^gmul(3,s[1][c])^s[2][c]^s[3][c];
        t[1]=s[0][c]^gmul(2,s[1][c])^gmul(3,s[2][c])^s[3][c];
        t[2]=s[0][c]^s[1][c]^gmul(2,s[2][c])^gmul(3,s[3][c]);
        t[3]=gmul(3,s[0][c])^s[1][c]^s[2][c]^gmul(2,s[3][c]);
        for(int i=0;i<4;i++) s[i][c]=t[i];
    }
}

void InvMixColumns(vector<vector<uint8_t>>& s){
    for(int c=0;c<4;c++){
        uint8_t t[4];
        t[0]=gmul(0x0E,s[0][c])^gmul(0x0B,s[1][c])^gmul(0x0D,s[2][c])^gmul(0x09,s[3][c]);
        t[1]=gmul(0x09,s[0][c])^gmul(0x0E,s[1][c])^gmul(0x0B,s[2][c])^gmul(0x0D,s[3][c]);
        t[2]=gmul(0x0D,s[0][c])^gmul(0x09,s[1][c])^gmul(0x0E,s[2][c])^gmul(0x0B,s[3][c]);
        t[3]=gmul(0x0B,s[0][c])^gmul(0x0D,s[1][c])^gmul(0x09,s[2][c])^gmul(0x0E,s[3][c]);
        for(int i=0;i<4;i++) s[i][c]=t[i];
    }
}

vector<vector<uint8_t>> mu_transform(vector<vector<uint8_t>> s) {
    // CORRECTED: Mathematical P^{-1} = SR^{-1} \circ MC^{-1}. Therefore, MC^{-1} happens first.
    InvMixColumns(s);
    InvShiftRows(s);
    return s;
}

void addRoundKey(vector<vector<uint8_t>>& s,const vector<uint8_t>& k){
    for(int c=0;c<4;c++)
        for(int r=0;r<4;r++)
            s[r][c]^=k[c*4+r];
}

// ================= KEY EXPANSION =================
void KeyExpansion(const array<uint8_t,16>& key,vector<array<uint8_t,4>>& w){
    w.resize(44);
    for(int i=0;i<4;i++) for(int j=0;j<4;j++) w[i][j]=key[4*i+j];

    for(int i=4;i<44;i++){
        auto temp=w[i-1];
        if(i%4==0){
            rotate(temp.begin(),temp.begin()+1,temp.end());
            for(auto& b:temp) b=s_box[b>>4][b&0xF];
            temp[0]^=RCon[i/4-1];
        }
        for(int j=0;j<4;j++) w[i][j]=w[i-4][j]^temp[j];
    }
}

// ================= ENCRYPT =================
vector<vector<uint8_t>> encrypt(vector<vector<uint8_t>> s,const vector<array<uint8_t,4>>& w){
    vector<uint8_t> rk;
    for(int i=0;i<4;i++) rk.insert(rk.end(),w[i].begin(),w[i].end());
    addRoundKey(s,rk);

    for(int r=1;r<=6;r++){
        rk.clear();
        for(int i=0;i<4;i++) rk.insert(rk.end(),w[r*4+i].begin(),w[r*4+i].end());
        apply_s_box(s);
        shiftRows(s);
        mixColumns(s);
        addRoundKey(s,rk);
    }

    rk.clear();
    for(int i=0;i<4;i++) rk.insert(rk.end(),w[28+i].begin(),w[28+i].end());
    apply_s_box(s);
    shiftRows(s);
    addRoundKey(s,rk);

    return s;
}

// ================= FIXED PARTIAL DECRYPT =================
vector<vector<uint8_t>> partialDecrypt(const vector<vector<uint8_t>>& Ci,const vector<uint8_t>& u){
    vector<vector<uint8_t>> s=Ci;

    InvShiftRows(s);

    for(int i=0;i<8;i++)
        s[i%4][i/4]^=u[i];

    InvSubBytes(s);
    InvMixColumns(s);
    InvShiftRows(s);

    return s;
}

// ================= MAIN =================
int main(){
    cout<<"RECTIFIED 7-ROUND ZERO-DIFFERENCE AES ATTACK RUNNING\n";

    random_device rd;
    mt19937 gen(rd());

    int m = 128; // Reduced for practical execution, theoretically 2^{55.1}

    vector<Vector8> A0(m), A1(m);
    for(int i=0;i<m;i++)
        for(int j=0;j<8;j++){
            A0[i][j]=getRandomHex(gen);
            A1[i][j]=getRandomHex(gen);
        }

    array<uint8_t,16> key;
    for(int i=0;i<16;i++) key[i]=getRandomHex(gen);

    vector<array<uint8_t,4>> w;
    KeyExpansion(key,w);

    vector<vector<uint8_t>> dx(4,vector<uint8_t>(4));
    vector<vector<uint8_t>> dxp(4,vector<uint8_t>(4));

    for(int i=0;i<4;i++)
        for(int j=0;j<4;j++)
            dx[i][j]=getRandomHex(gen);

    dxp[0][0]=getRandomHex(gen); dxp[0][2]=getRandomHex(gen);
    dxp[1][1]=getRandomHex(gen); dxp[1][3]=getRandomHex(gen);
    dxp[2][0]=getRandomHex(gen); dxp[2][2]=getRandomHex(gen);
    dxp[3][1]=getRandomHex(gen); dxp[3][3]=getRandomHex(gen);

    list<Quartet_Record> N2;

    cout << "Step 1, 2 & 3: Generating strict Cartesian quartets and isolating double collisions...\n";

    for(int i=0;i<m;i++){
        for(int j=0;j<m;j++){

            vector<vector<uint8_t>> P0(4,vector<uint8_t>(4));

            // CORRECTED: Explicitly map elements to the exact Diagonals
            P0[0][0]=A0[i][0]; P0[1][1]=A0[i][1]; P0[2][2]=A0[i][2]; P0[3][3]=A0[i][3];
            P0[0][2]=A0[i][4]; P0[1][3]=A0[i][5]; P0[2][0]=A0[i][6]; P0[3][1]=A0[i][7];
            
            P0[0][1]=A1[j][0]; P0[1][2]=A1[j][1]; P0[2][3]=A1[j][2]; P0[3][0]=A1[j][3];
            P0[0][3]=A1[j][4]; P0[1][0]=A1[j][5]; P0[2][1]=A1[j][6]; P0[3][2]=A1[j][7];

            auto P1=matrixXor(P0,dxp);
            auto P2=matrixXor(P0,dx);
            auto P3=matrixXor(P2,dxp);

            auto C0=encrypt(P0,w);
            auto C1=encrypt(P1,w);
            auto C2=encrypt(P2,w);
            auto C3=encrypt(P3,w);

            auto mu01=mu_transform(matrixXor(C0,C1));
            auto mu23=mu_transform(matrixXor(C2,C3));

            if(countActiveColumns(mu01)==2 && matricesEqual(mu01,mu23))
                N2.push_back({C0,C1,C2,C3});
        }
    }

    cout<<"N2 size: "<<N2.size()<<endl;

    // --- STEPS 4 to 16: Key Candidate Pruning and Verification ---
    cout << "Step 4: Executing equivalent round-key pruning on candidates...\n";
    for (const auto& quartet : N2) {
        vector<vector<uint8_t>> valid_u7_candidates(8);
        bool quartet_survives = true;

        // Alignment tracking: Unshift before isolating active columns for zero-sum check
        vector<vector<uint8_t>> C0_unshifted = quartet.C0; InvShiftRows(C0_unshifted);
        vector<vector<uint8_t>> C1_unshifted = quartet.C1; InvShiftRows(C1_unshifted);
        vector<vector<uint8_t>> C2_unshifted = quartet.C2; InvShiftRows(C2_unshifted);
        vector<vector<uint8_t>> C3_unshifted = quartet.C3; InvShiftRows(C3_unshifted);

        for (int i = 0; i < 8; ++i) {
            for (int u = 0; u < 256; ++u) {
                uint8_t test_val = static_cast<uint8_t>(u);
                
                // Zero-Sum evaluation over the exact byte indices using correct alignment
                if ((inverseSBox(getByteColMajor(C0_unshifted, i) ^ test_val) ^
                     inverseSBox(getByteColMajor(C1_unshifted, i) ^ test_val) ^
                     inverseSBox(getByteColMajor(C2_unshifted, i) ^ test_val) ^
                     inverseSBox(getByteColMajor(C3_unshifted, i) ^ test_val)) == 0) {
                    
                    valid_u7_candidates[i].push_back(test_val);
                }
            }
            if (valid_u7_candidates[i].empty()) {
                quartet_survives = false;
                break;
            }
        }

        if (quartet_survives) {
            vector<vector<uint8_t>> all_combinations;
            vector<uint8_t> current_combo(8, 0);
            
            build_combinations(valid_u7_candidates, 0, current_combo, all_combinations);
            
            for (const auto& u_guess : all_combinations) {
                auto Y_C0 = partialDecrypt(quartet.C0, u_guess);
                auto Y_C2 = partialDecrypt(quartet.C2, u_guess);
                auto Y_C3 = partialDecrypt(quartet.C3, u_guess);

                auto diff_02 = matrixXor(Y_C0, Y_C2);
                auto diff_03 = matrixXor(Y_C0, Y_C3);

                // Validation filter enforcing strict structure over the remaining rounds
                if (countActiveFirstTwoDiagonals(diff_02) == 2 && 
                    countActiveFirstTwoDiagonals(diff_03) == 2 && 
                    countActiveBytes(diff_02) == 2 && 
                    countActiveBytes(diff_03) == 2) {
                    
                    cout << "\n[+] Valid Partial Candidate found! Preparing Exhaustive Search...\n";
                    cout << "Partial Equivalent Key (u7): [ ";
                    for(int k=0; k<8; k++) cout << hex << (int)u_guess[k] << " ";
                    cout << dec << "]\n";
                }
            }
        }
    }

    cout << "DONE\n";
    return 0;
}
