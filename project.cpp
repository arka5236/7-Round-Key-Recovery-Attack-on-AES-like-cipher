#include <iostream>
#include <iomanip>   // for setw and setfill
#include <vector>
#include <array>
#include <random>
#include <cstdint>
#include<algorithm>
#include<list>
#include<tuple>
#include<cmath>

using namespace std;

// AES S-Box
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
void apply_s_box(vector<vector<uint8_t>>& matrix) {
  for (auto& row : matrix) {
      for (auto& val : row) {
          val = s_box[val >> 4][val & 0x0F];
      }
  }
}
// AES Inverse S-Box
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

// Function to apply the Inverse S-Box to a 4x4 matrix represented as a vector of vectors.
void InvSubBytes(vector<vector<uint8_t>> &matrix) {
    for (size_t i = 0; i < matrix.size(); ++i) {
        for (size_t j = 0; j < matrix[i].size(); ++j) {
            uint8_t byte = matrix[i][j];
            uint8_t highNibble = (byte >> 4) & 0x0F; // Extract top 4 bits
            uint8_t lowNibble = byte & 0x0F;         // Extract bottom 4 bits
            matrix[i][j] = inv_s_box[highNibble][lowNibble]; // Substitute using the inverse S-box
        }
    }
}

void shiftRows(vector<vector<uint8_t>>& matrix) {
    uint8_t temp;
  
    // Ensure that the matrix has 4 rows and each row has 4 columns.
    if (matrix.size() != 4 || matrix[0].size() != 4) {
        cerr << "Error: The matrix must be 4x4." << endl;
        return;
    }
    
    // Shift the second row (row 1) one position to the left.
    temp = matrix[1][0];
    for (int i = 0; i < 3; i++) {
        matrix[1][i] = matrix[1][i + 1];
    }
    matrix[1][3] = temp;
    
    // Shift the third row (row 2) by 2 positions to the left.
    // We swap corresponding elements: positions 0 and 2, then positions 1 and 3.
    temp = matrix[2][0];
    matrix[2][0] = matrix[2][2];
    matrix[2][2] = temp;
    
    temp = matrix[2][1];
    matrix[2][1] = matrix[2][3];
    matrix[2][3] = temp;
    
    // Shift the fourth row (row 3) by 3 positions to the left (or equivalently right by 1 position).
    temp = matrix[3][3];
    for (int i = 3; i > 0; i--) {
        matrix[3][i] = matrix[3][i - 1];
    }
    matrix[3][0] = temp;
}

// Function to multiply by 2 in GF(2^8)
unsigned char xtime(unsigned char x) {
    return (x << 1) ^ ((x >> 7) & 1 ? 0x1B : 0);
}

// Function to multiply two bytes in GF(2^8)
unsigned char multiply(unsigned char x, unsigned char y) {
    return ((y & 1) * x) ^
           ((y >> 1 & 1) * xtime(x)) ^
           ((y >> 2 & 1) * xtime(xtime(x))) ^
           ((y >> 3 & 1) * xtime(xtime(xtime(x)))) ^
           ((y >> 4 & 1) * xtime(xtime(xtime(xtime(x)))));
}

void mixColumns(vector<vector<uint8_t>>& state) {
    // Check that the state is a 4x4 matrix.
    if (state.size() != 4) {
        cerr << "Error: The matrix must have 4 rows." << endl;
        return;
    }
    for (int i = 0; i < 4; i++) {
        if (state[i].size() != 4) {
            cerr << "Error: Each row in the matrix must have 4 columns." << endl;
            return;
        }
    }
    
    // Process each column independently.
    for (int i = 0; i < 4; i++) {
        unsigned char temp[4];
        temp[0] = multiply(0x02, state[0][i]) ^ multiply(0x03, state[1][i]) ^ state[2][i] ^ state[3][i];
        temp[1] = state[0][i] ^ multiply(0x02, state[1][i]) ^ multiply(0x03, state[2][i]) ^ state[3][i];
        temp[2] = state[0][i] ^ state[1][i] ^ multiply(0x02, state[2][i]) ^ multiply(0x03, state[3][i]);
        temp[3] = multiply(0x03, state[0][i]) ^ state[1][i] ^ state[2][i] ^ multiply(0x02, state[3][i]);
        
        // Write the computed values back into the state.
        for (int j = 0; j < 4; j++) {
            state[j][i] = temp[j];
        }
    }
}

const uint8_t RCon[10] = {0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36};

void RotWord(array<uint8_t, 4>& word) {
  uint8_t temp = word[0];
  word[0] = word[1];
  word[1] = word[2];
  word[2] = word[3];
  word[3] = temp;
}

void SubWord(array<uint8_t, 4>& word) {
  for (int i = 0; i < 4; ++i) {
      word[i] = s_box[word[i] >> 4][word[i] & 0x0F];
  }
}

void KeyExpansion(const array<uint8_t, 16>& key, vector<array<uint8_t, 4>>& expandedKeys) {
  expandedKeys.resize(44);
  for (int i = 0; i < 4; ++i) {
      for (int j = 0; j < 4; ++j) {
          expandedKeys[i][j] = key[4 * i + j];
      }
  }

  array<uint8_t, 4> temp;
  for (int i = 4; i < 44; ++i) {
      temp = expandedKeys[i - 1];
      if (i % 4 == 0) {
          RotWord(temp);
          SubWord(temp);
          temp[0] ^= RCon[(i / 4) - 1];
      }
      for (int j = 0; j < 4; ++j) {
          expandedKeys[i][j] = expandedKeys[i - 4][j] ^ temp[j];
      }
  }
}

// Function to generate a random 8-bit value (0x00 to 0xFF)
uint8_t getRandomHex_1(mt19937 &gen) {
    uniform_int_distribution<> dist(0, 255);
    return static_cast<uint8_t>(dist(gen));
}

// Function to create a random initial key as a 4x4 matrix.
vector<vector<uint8_t>> createRandomInitialKey(mt19937 &gen) {
    vector<vector<uint8_t>> key(4, vector<uint8_t>(4, 0));
    for (int i = 0; i < 4; i++) {
        for (int j = 0; j < 4; j++) {
            key[i][j] = getRandomHex_1(gen);
        }
    }
    return key;
}

vector<uint8_t> flattenMatrix(const vector<vector<uint8_t>> &matrix) {
  vector<uint8_t> flat;
  for (int col = 0; col < 4; col++) {
      for (int row = 0; row < 4; row++) {
          flat.push_back(matrix[row][col]);
      }
  }
  return flat;
}




void addRoundKey(vector<vector<uint8_t>>& state, const vector<uint8_t>& roundKey) {
    // Verify that the state is 4x4 and the round key has 16 bytes.
    if (state.size() != 4 || state[0].size() != 4 || roundKey.size() != 16) {
        cerr << "Error: The state must be a 4x4 matrix and the round key must have 16 bytes." << endl;
        return;
    }
    
    // For each cell in the state matrix, XOR it with the corresponding byte from the round key.
    // The round key is assumed to be in row-major order: index = row * 4 + column.
    for (size_t i = 0; i < 4; i++) {
        for (size_t j = 0; j < 4; j++) {
            state[i][j] ^= roundKey[i * 4 + j];
        }
    }
}


// Function to print the 7th round key in matrix form
void print7thRoundKey(const array<uint8_t, 16>& initialKey) {
    vector<array<uint8_t, 4>> expandedKeys;
    KeyExpansion(initialKey, expandedKeys);

    cout << "7th Round Key:\n";
    for (int i = 24; i < 28; ++i) {
        for (int j = 0; j < 4; ++j) {
            cout << hex << setw(2) << setfill('0') << (int)expandedKeys[i][j] << " ";
        }
        cout << endl;
    }
    cout << endl;
}

// Helper function to print a 4x4 matrix in hexadecimal format.
void printMatrix(const vector<vector<uint8_t>>& matrix) {
    for (const auto& row : matrix) {
        for (const auto& byte : row) {
            cout << "0x" << hex << setw(2) << setfill('0') << static_cast<int>(byte) << " ";
        }
        cout << "\n";
    }
    cout << dec;
}



// Optional: A helper function to print a vector of bytes in hexadecimal.
void printKey(const std::vector<uint8_t>& key) {
    for (size_t i = 0; i < key.size(); i++) {
        printf("0x%02X ", key[i]);
    }
    printf("\n");
}




// Represent an element of F_(2^8)^8 as an array of 8 uint8_t values.
using Vector8 = array<uint8_t, 8>;

// Function to generate a random vector in F_(2^8)^8.
Vector8 generate_random_vector(mt19937 &gen) {
    Vector8 vec;
    // Uniform distribution over [0, 255] for 8-bit values.
    uniform_int_distribution<> dist(0, 255);
    for (int i = 0; i < 8; i++) {
        vec[i] = static_cast<uint8_t>(dist(gen));
    }
    return vec;
}

// Function to generate a random subset of F_(2^8)^8 with m elements.
vector<Vector8> generate_random_subset(int m, mt19937 &gen) {
    vector<Vector8> subset;
    subset.reserve(m);
    for (int i = 0; i < m; i++) {
        subset.push_back(generate_random_vector(gen));
    }
    return subset;
}

// Helper function to print a vector in hex format.
void print_vector8(const Vector8 &vec) {
    for (int i = 0; i < 8; i++) {
        // Print each number as a two-digit hexadecimal value.
        cout << "0x" 
             << hex << setw(2) << setfill('0')
             << static_cast<int>(vec[i]) << " ";
    }
    cout << dec << "\n"; // Reset output to decimal.
}

// Helper function to print a 4x4 matrix of Vector8 elements.
void printMatrix(const vector<vector<Vector8>> &matrix) {
    for (const auto &row : matrix) {
        for (const auto &elem : row) {
            cout << "[ ";
            for (int i = 0; i < 8; i++) {
                cout << "0x" << hex << setw(2) << setfill('0')
                     << static_cast<int>(elem[i]) << " ";
            }
            cout << "]  ";
        }
        cout << "\n";
    }
    cout << dec;
}

// Helper function to print a 4x4 matrix of single bytes in hexadecimal format.
void printMatrixByte(const vector<vector<uint8_t>> &matrix) {
    for (const auto &row : matrix) {
        for (const auto &elem : row) {
            cout << "0x" 
                 << hex << setw(2) << setfill('0')
                 << static_cast<int>(elem) << " ";
        }
        cout << "\n";
    }
    cout << dec;
}

// Galois Field multiplication (GF(2^8))
uint8_t gmul(uint8_t a, uint8_t b) {
    uint8_t p = 0; // Product
    for (int i = 0; i < 8; i++) {
        if (b & 1) {
            p ^= a;
        }
        uint8_t carry = a & 0x80;
        a <<= 1;
        if (carry) {
            a ^= 0x1b; // AES irreducible polynomial: x^8 + x^4 + x^3 + x + 1
        }
        b >>= 1;
    }
    return p;
}

void InvMixColumns(vector<vector<uint8_t>> &state) {
    uint8_t temp[4];
    // Process each column
    for (int c = 0; c < 4; c++) {
        temp[0] = gmul(0x0E, state[0][c]) ^ gmul(0x0B, state[1][c]) ^ gmul(0x0D, state[2][c]) ^ gmul(0x09, state[3][c]);
        temp[1] = gmul(0x09, state[0][c]) ^ gmul(0x0E, state[1][c]) ^ gmul(0x0B, state[2][c]) ^ gmul(0x0D, state[3][c]);
        temp[2] = gmul(0x0D, state[0][c]) ^ gmul(0x09, state[1][c]) ^ gmul(0x0E, state[2][c]) ^ gmul(0x0B, state[3][c]);
        temp[3] = gmul(0x0B, state[0][c]) ^ gmul(0x0D, state[1][c]) ^ gmul(0x09, state[2][c]) ^ gmul(0x0E, state[3][c]);
        // Write back the computed column
        for (int i = 0; i < 4; i++) {
            state[i][c] = temp[i];
        }
    }
}

void InvShiftRows(vector<vector<uint8_t>> &state) {
    uint8_t temp;
    // Row 0 remains unchanged.
    
    // Row 1: shift one position to the right.
    temp = state[1][3];
    state[1][3] = state[1][2];
    state[1][2] = state[1][1];
    state[1][1] = state[1][0];
    state[1][0] = temp;
    
    // Row 2: shift two positions to the right.
    // Swap elements: positions 0 and 2, and positions 1 and 3.
    temp = state[2][0];
    state[2][0] = state[2][2];
    state[2][2] = temp;
    temp = state[2][1];
    state[2][1] = state[2][3];
    state[2][3] = temp;
    
    // Row 3: shift three positions to the right (equivalently, one position to the left).
    temp = state[3][0];
    state[3][0] = state[3][1];
    state[3][1] = state[3][2];
    state[3][2] = state[3][3];
    state[3][3] = temp;
}

// Function to get a single random byte from a randomly chosen tuple in the subset.
uint8_t get_random_byte_from_subset(const vector<Vector8> &subset, mt19937 &gen) {
    // Choose a random tuple index.
    uniform_int_distribution<> tuple_dist(0, subset.size() - 1);
    // Choose a random position within the 8-tuple.
    uniform_int_distribution<> pos_dist(0, 7);
    int tuple_index = tuple_dist(gen);
    int byte_index = pos_dist(gen);
    return subset[tuple_index][byte_index];
}

// Function to generate a random hexadecimal number (8-bit)
uint8_t getRandomHex(mt19937& gen) {
    uniform_int_distribution<> dist(0, 255); // Hex range: 0x00 to 0xFF
    return static_cast<uint8_t>(dist(gen));
}

// Function to create del_x_prime matrix
vector<vector<uint8_t>> createDelXPrime(mt19937& gen) {
    // Initialize a 4x4 matrix with zeros
    vector<vector<uint8_t>> del_x_prime(4, vector<uint8_t>(4, 0));

    // Fill the matrix based on the given pattern
    del_x_prime[0][0] = getRandomHex(gen); // ∆x0
    del_x_prime[0][2] = getRandomHex(gen); // ∆x8

    del_x_prime[1][1] = getRandomHex(gen); // ∆x5
    del_x_prime[1][3] = getRandomHex(gen); // ∆x13

    del_x_prime[2][0] = getRandomHex(gen); // ∆x2
    del_x_prime[2][2] = getRandomHex(gen); // ∆x10

    del_x_prime[3][1] = getRandomHex(gen); // ∆x7
    del_x_prime[3][3] = getRandomHex(gen); // ∆x1

    return del_x_prime;
}

vector<vector<uint8_t>> createDelX(int rows, int cols, mt19937& gen) {
    vector<vector<uint8_t>> matrix(rows, vector<uint8_t>(cols, 0));
    for (int i = 0; i < rows; i++) {
        for (int j = 0; j < cols; j++) {
            matrix[i][j] = getRandomHex(gen);
        }
    }
    return matrix;
}

bool areRelatedDifferenceMatrices(const vector<vector<uint8_t>>& del_x,
    const vector<vector<uint8_t>>& del_x_prime) {
size_t rows = del_x.size();
size_t cols = (rows > 0 ? del_x[0].size() : 0);

// Ensure matrices have the same dimensions
if (rows != del_x_prime.size() || (rows > 0 && cols != del_x_prime[0].size())) {
cout << "Error: Matrices must have the same dimensions!" << endl;
return false;
}

// Check the condition for each element.
// For each cell (i, j), we take its value from each of the matrices and compute:
//   condition = delta_x_value * delta_x_prime_value * (delta_x_value XOR delta_x_prime_value)
// If condition != 0 for any element, the matrices do not represent related differences.
for (size_t i = 0; i < rows; ++i) {
for (size_t j = 0; j < cols; ++j) {
uint8_t delta_x_value = del_x[i][j];
uint8_t delta_x_prime_value = del_x_prime[i][j];

uint8_t condition = delta_x_value * delta_x_prime_value * (delta_x_value ^ delta_x_prime_value);
if (condition != 0) {
return false; // As soon as one cell fails, the matrices are not "related differences."
}
}
}
return true; // All cells satisfy the condition.
}

void zeroDifferencePattern(const vector<vector<uint8_t>>& matrix, vector<vector<int>>& pattern) {
    int rows = matrix.size();
    int cols = (rows > 0 ? matrix[0].size() : 0);

    // Resize the pattern matrix to the same 2D dimensions as the input
    pattern.resize(rows, vector<int>(cols, 0));

    // Iterate over the matrix elements and mark positions that are zero.
    for (int i = 0; i < rows; ++i) {
        for (int j = 0; j < cols; ++j) {
            // If the element is zero, mark it as 1 in the pattern (otherwise, mark 0)
            pattern[i][j] = (matrix[i][j] == 0) ? 1 : 0;
        }
    }
}

// A simple helper function to print the pattern matrix.
void printPattern(const vector<vector<int>>& pattern) {
    for (const auto& row : pattern) {
        for (const auto& elem : row) {
            cout << elem << " ";
        }
        cout << "\n";
    }
}

int hammingWeight(uint8_t n) {
    int count = 0;
    while (n) {
        n &= (n - 1); // Clear the least significant bit set
        ++count;
    }
    return count;
}


int calculateHammingWeightXor(const vector<vector<uint8_t>>& matrix1,
    const vector<vector<uint8_t>>& matrix2) {
// Check that matrix dimensions match.
if (matrix1.size() != matrix2.size() || (matrix1.size() > 0 && matrix1[0].size() != matrix2[0].size())) {
cerr << "Error: Matrices must have the same dimensions!" << endl;
return -1; // Return an error indicator.
}

int totalWeight = 0;

// Iterate over each element, XOR the two matrices element-wise, and accumulate the Hamming weight.
for (size_t i = 0; i < matrix1.size(); ++i) {
for (size_t j = 0; j < matrix1[i].size(); ++j) {
uint8_t xored = matrix1[i][j] ^ matrix2[i][j];
totalWeight += hammingWeight(xored);
}
}

return totalWeight;
}

vector<vector<uint8_t>> matrixXor(const vector<vector<uint8_t>>& A,
    const vector<vector<uint8_t>>& B) {
size_t rows = A.size();
size_t cols = (rows > 0 ? A[0].size() : 0);
vector<vector<uint8_t>> result(rows, vector<uint8_t>(cols, 0));
for (size_t i = 0; i < rows; i++) {
for (size_t j = 0; j < cols; j++) {
result[i][j] = A[i][j] ^ B[i][j];
}
}
return result;
}

bool areMatricesEqual(const vector<vector<uint8_t>>& A,
    const vector<vector<uint8_t>>& B) {
if (A.size() != B.size()) return false;
for (size_t i = 0; i < A.size(); i++) {
if (A[i].size() != B[i].size()) return false;
for (size_t j = 0; j < A[i].size(); j++) {
if (A[i][j] != B[i][j]) return false;
}
}
return true;
}

// Function to calculate total Hamming weight of a 4×4 binary matrix
int matrixHammingWeight(const vector<vector<uint8_t>> &matrix) {
    int totalWeight = 0;
    for (const auto &row : matrix) {
        for (const auto &elem : row) {
            totalWeight += hammingWeight(elem);
        }
    }
    return totalWeight;
}

// Function to calculate total Hamming weight of a 4×4 integer matrix
int matrixHammingWeight_int(const vector<vector<int>> &matrix) {
    int totalWeight = 0;
    for (const auto &row : matrix) {
        for (const auto &elem : row) {
            totalWeight += hammingWeight(elem);
        }
    }
    return totalWeight;
}

// Function to generate an array of 256 hexadecimal numbers
vector<uint8_t> generateHexArray() {
    vector<uint8_t> hexArray(256);
    for (int i = 0; i < 256; i++) {
        hexArray[i] = static_cast<uint8_t>(i);
    }
    return hexArray;
}

// Inverse S-box function: uses the 16x16 table
uint8_t inverseSBox(uint8_t val) {
    uint8_t row = val >> 4;      // high nibble
    uint8_t col = val & 0x0F;      // low nibble
    return static_cast<uint8_t>(inv_s_box[row][col]);
}

// Helper: Get the i-th byte (in row-major order) from a 4x4 matrix.
uint8_t getByte(const vector<vector<uint8_t>>& matrix, int i) {
    int row = i / 4;  // each row has 4 bytes in a 4x4 matrix
    int col = i % 4;
    return matrix[row][col];
}

// -------------------------------------------------------------------
// Partially decrypt the first two columns of Ci using
// Y = SR⁻¹ ∘ MC⁻¹ ∘ SB⁻¹, with u = { u0^7, ..., u7^7 }.
// This function returns a 4x2 matrix (partial decryption result).

vector<vector<uint8_t>> partialDecryptFirstTwoColumns(
    const vector<vector<uint8_t>> &Ci, 
    const vector<uint8_t> &u)
{
    if (u.size() != 8) {
        cerr << "Error: Expected 8 bytes in u" << endl;
        return vector<vector<uint8_t>>();
    }
    
    // Build a full 4x4 state.
    // Copy the first two columns from Ci; set columns 2 and 3 to 0.
    vector<vector<uint8_t>> state(4, vector<uint8_t>(4, 0));
    for (int row = 0; row < 4; row++) {
        state[row][0] = Ci[row][0];
        state[row][1] = Ci[row][1];
    }
    
    // XOR the first two columns with u (row-major order: indices 0..7).
    int index = 0;
    for (int row = 0; row < 4; row++) {
        for (int col = 0; col < 2; col++) {
            state[row][col] ^= u[index++];
        }
    }
    
    // Apply Inverse SubBytes (SB⁻¹) on the entire state.
    for (int row = 0; row < 4; row++) {
        for (int col = 0; col < 4; col++) {
            state[row][col] = inverseSBox(state[row][col]);
        }
    }
    
    // Apply Inverse MixColumns (MC⁻¹).
    InvMixColumns(state);
    // Apply Inverse ShiftRows (SR⁻¹).
    InvShiftRows(state);
    
    // Extract the first two columns (4x2 block) as the result.
    vector<vector<uint8_t>> decryptedPartial(4, vector<uint8_t>(2, 0));
    for (int row = 0; row < 4; row++) {
        decryptedPartial[row][0] = state[row][0];
        decryptedPartial[row][1] = state[row][1];
    }
    
    return decryptedPartial;
}

// Helper: XOR two 4x2 matrices element-wise.
vector<vector<uint8_t>> xorPartialMatrices(const vector<vector<uint8_t>> &A,
    const vector<vector<uint8_t>> &B)
{
vector<vector<uint8_t>> result(4, vector<uint8_t>(2, 0));
for (int row = 0; row < 4; row++) {
for (int col = 0; col < 2; col++) {
result[row][col] = A[row][col] ^ B[row][col];
}
}
return result;
}

// Helper: Count active (nonzero) bytes in the top-2x2 block
// (i.e. positions (0,0), (0,1), (1,0), and (1,1)).
int countActiveTop2x2(const vector<vector<uint8_t>> &mat) {
    int count = 0;
    for (int row = 0; row < 2; row++) {
        for (int col = 0; col < 2; col++) {
            if (mat[row][col] != 0)
                count++;
        }
    }
    return count;
}

std::vector<std::vector<uint8_t>> partialDecryptFull(std::vector<std::vector<uint8_t>> state, const std::vector<uint8_t>& fullRoundKey) {
    std::vector<std::vector<uint8_t>> decrypted_state = state;
    std::vector<std::vector<uint8_t>> key_matrix(4, std::vector<uint8_t>(4));
    for (int i = 0; i < 4; ++i) {
        for (int j = 0; j < 4; ++j) {
            key_matrix[i][j] = fullRoundKey[i * 4 + j];
        }
    }

    for (int i = 0; i < 4; ++i) {
        for (int j = 0; j < 4; ++j) {
            decrypted_state[i][j] ^= key_matrix[i][j];
        }
    }
    return decrypted_state;
}

std::vector<std::vector<uint8_t>> partialDecryptFirstTwoColumns(std::vector<std::vector<uint8_t>> state, const std::vector<uint8_t>& keyBytes) {
    std::vector<std::vector<uint8_t>> decrypted_state = state;
    std::vector<std::vector<uint8_t>> key_matrix(4, std::vector<uint8_t>(4, 0));
    for (int i = 0; i < 4; ++i) {
        if (i < keyBytes.size() / 2) {
            key_matrix[i][0] = keyBytes[i * 2];
            key_matrix[i][1] = keyBytes[i * 2 + 1];
        }
    }

    for (int i = 0; i < 4; ++i) {
        decrypted_state[i][0] ^= key_matrix[i][0];
        decrypted_state[i][1] ^= key_matrix[i][1];
    }
    return decrypted_state;
}

// Function to perform one round of encryption
std::vector<std::vector<uint8_t>> encryptRound(std::vector<std::vector<uint8_t>> state, const std::vector<uint8_t>& roundKey) {
    apply_s_box(state);
    shiftRows(state);
    mixColumns(state);
    addRoundKey(state, roundKey);
    return state;
}

vector<vector<uint8_t>> encrypt(vector<vector<uint8_t>> plaintext, const vector<array<uint8_t, 4>>& expandedKeys) {
  vector<vector<uint8_t>> state = plaintext;

  // Get the initial round key (first 4 words)
  vector<uint8_t> initialRoundKey;
  for (int i = 0; i < 4; ++i)
      initialRoundKey.insert(initialRoundKey.end(), expandedKeys[i].begin(), expandedKeys[i].end());

  addRoundKey(state, initialRoundKey);

  for (int round = 1; round <= 7; ++round) {
      vector<uint8_t> roundKey;
      for (int i = 0; i < 4; ++i)
          roundKey.insert(roundKey.end(), expandedKeys[round * 4 + i].begin(), expandedKeys[round * 4 + i].end());

      state = encryptRound(state, roundKey);
  }

  return state;
}


// Function to print the 6th round key in matrix form
void print6thRoundKey(const array<uint8_t, 16>& initialKey) {
    vector<array<uint8_t, 4>> expandedKeys;
    KeyExpansion(initialKey, expandedKeys);

    cout << "6th Round Key:\n";
    for (int i = 20; i < 24; ++i) {
        for (int j = 0; j < 4; ++j) {
            cout << hex << setw(2) << setfill('0') << (int)expandedKeys[i][j] << " ";
        }
        cout << endl;
    }
    cout << endl;
}


int main() {
    int m = 256;

    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<uint8_t> dist(0, 255);

    std::vector<Vector8> A0 = generate_random_subset(m, gen);
    std::vector<Vector8> A1 = generate_random_subset(m, gen);

    std::list<std::pair<std::vector<std::vector<uint8_t>>, std::vector<std::vector<uint8_t>>>> N1;
    std::list<std::tuple<std::vector<std::vector<uint8_t>>, std::vector<std::vector<uint8_t>>, std::vector<std::vector<uint8_t>>, std::vector<std::vector<uint8_t>>>> N2;

    double num_plaintexts = 1000;
    std::vector<uint8_t> initialKeyVec = flattenMatrix(createRandomInitialKey(gen));

    // Convert vector to array
    std::array<uint8_t, 16> initialKey;
    std::copy(initialKeyVec.begin(), initialKeyVec.end(), initialKey.begin());
    
    vector<array<uint8_t, 4>> expandedKeys(44);
    KeyExpansion(initialKey, expandedKeys);

    // Print the 7th round key
    print7thRoundKey(initialKey);
    print6thRoundKey(initialKey);
    

    std::vector<std::vector<uint8_t>> delta_x_prime = createDelXPrime(gen);
    std::vector<std::vector<uint8_t>> delta_x = createDelX(4, 4, gen);

    // Store P0 here
 std::vector<std::vector<uint8_t>> stored_P0(4, std::vector<uint8_t>(4, 0));

    for (int i = 0; i < num_plaintexts; ++i) { // Limit for demonstration
        std::vector<std::vector<uint8_t>> P0(4, std::vector<uint8_t>(4, 0));
        std::vector<std::vector<uint8_t>> P0_prime = P0;

        for (int j = 0; j < 4; ++j) {
            P0[j][j] = get_random_byte_from_subset(A0, gen);
            if (j < 3) P0[j][j + 1] = get_random_byte_from_subset(A0, gen);
            P0[j][3 - j] = get_random_byte_from_subset(A1, gen);
            if (j < 3) P0[j + 1][j] = get_random_byte_from_subset(A1, gen);
        }
        P0_prime = matrixXor(P0, delta_x_prime);

        std::vector<std::vector<uint8_t>> C0 = encrypt(P0, expandedKeys);
        std::vector<std::vector<uint8_t>> C0_prime = encrypt(P0_prime, expandedKeys);

        std::vector<std::vector<int>> pattern;
        std::vector<std::vector<uint8_t>> diff_C = matrixXor(C0, C0_prime);
        InvMixColumns(diff_C);
        InvShiftRows(diff_C);
        zeroDifferencePattern(diff_C, pattern);

        if (matrixHammingWeight_int(pattern) == 2) {
            N1.push_back({C0, C0_prime});
            //Store the P0
            stored_P0 = P0;
        }
    }

    std::cout << "Size of N1: " << N1.size() << std::endl;

    for (const auto& pair : N1) {
        std::vector<std::vector<uint8_t>> C0 = pair.first;
        std::vector<std::vector<uint8_t>> C0_prime = pair.second;

        // Use the stored P0, not a new one
        std::vector<std::vector<uint8_t>> P0 = stored_P0;
       
        std::vector<std::vector<uint8_t>> P1 = matrixXor(P0, delta_x);
        std::vector<std::vector<uint8_t>> P2 = matrixXor(P0, delta_x_prime);
        std::vector<std::vector<uint8_t>> P3 = matrixXor(P0, matrixXor(delta_x, delta_x_prime));

        std::vector<std::vector<uint8_t>> C1 = encrypt(P1, expandedKeys);
        std::vector<std::vector<uint8_t>> C2_temp = encrypt(P2, expandedKeys);
        std::vector<std::vector<uint8_t>> C3_temp = encrypt(P3, expandedKeys);

        // In a real scenario, N2 would be populated based on the plaintext relationships.
        // For demonstration, let's assume we have a way to get a valid quartet.
        N2.emplace_back(C0, C1, C2_temp, C3_temp); // Simplified population for demonstration
    }

    std::cout << "Size of N2 (after potential population): " << N2.size() << std::endl;

    for (const auto& quartet : N2) {
        std::vector<std::vector<uint8_t>> C0, C1, C2, C3;
        std::tie(C0, C1, C2, C3) = quartet;
        std::vector<uint8_t> possible_u7_partial(8);
        std::vector<uint8_t> candidates_u7_full(16);
        bool possible_partial = true;

        for (int i = 0; i < 8; ++i) {
            std::vector<uint8_t> candidates_ui7;
            for (int u = 0; u < 256; ++u) {
                if ((inverseSBox(getByte(C0, i) ^ static_cast<uint8_t>(u)) ^
                     inverseSBox(getByte(C1, i) ^ static_cast<uint8_t>(u)) ^
                     inverseSBox(getByte(C2, i) ^ static_cast<uint8_t>(u)) ^
                     inverseSBox(getByte(C3, i) ^ static_cast<uint8_t>(u))) == 0) {
                    candidates_ui7.push_back(static_cast<uint8_t>(u));
                }
            }

            if (candidates_ui7.empty()) {
                possible_partial = false;
                break;
            }
            possible_u7_partial[i] = candidates_ui7[0]; // Taking the first candidate for now
        }

        if (possible_partial) {
            std::cout << "Potential partial last round key (first 8 bytes):" << std::endl;
            for (int i = 0; i < 8; ++i) {
                std::cout << "Byte " << i << ": 0x" << std::hex << static_cast<int>(possible_u7_partial[i]) << std::endl;
                candidates_u7_full[i] = possible_u7_partial[i];
            }

            std::cout << "Starting exhaustive search for the remaining 8 bytes of the last round key..." << std::endl;
            for (int b8 = 0; b8 < 256; ++b8) {
                for (int b9 = 0; b9 < 256; ++b9) {
                    for (int b10 = 0; b10 < 256; ++b10) {
                        for (int b11 = 0; b11 < 256; ++b11) {
                            for (int b12 = 0; b12 < 256; ++b12) {
                                for (int b13 = 0; b13 < 256; ++b13) {
                                    for (int b14 = 0; b14 < 256; ++b14) {
                                        for (int b15 = 0; b15 < 256; ++b15) {
                                            std::vector<uint8_t> u7_full = {
                                                possible_u7_partial[0], possible_u7_partial[1], possible_u7_partial[2], possible_u7_partial[3],
                                                possible_u7_partial[4], possible_u7_partial[5], possible_u7_partial[6], possible_u7_partial[7],
                                                static_cast<uint8_t>(b8), static_cast<uint8_t>(b9), static_cast<uint8_t>(b10), static_cast<uint8_t>(b11),
                                                static_cast<uint8_t>(b12), static_cast<uint8_t>(b13), static_cast<uint8_t>(b14), static_cast<uint8_t>(b15)
                                            };
                                            InvMixColumns(C0);
                                            InvMixColumns(C2);
                                            InvMixColumns(C3);
                                            InvShiftRows(C0);
                                            InvShiftRows(C2);
                                            InvShiftRows(C3);
                                            

                                            std::vector<std::vector<uint8_t>> Y_C0 = partialDecryptFull((C0), u7_full);
                                            std::vector<std::vector<uint8_t>> Y_C2 = partialDecryptFull(C2, u7_full);
                                            std::vector<std::vector<uint8_t>> Y_C3 = partialDecryptFull(C3, u7_full);

                                            std::vector<std::vector<uint8_t>> diff_Y02 = matrixXor(Y_C0, Y_C2);
                                            std::vector<std::vector<uint8_t>> diff_Y03 = matrixXor(Y_C0, Y_C3);

                                            int active_02 = 0;
                                            int active_03 = 0;
                                            for (int r = 0; r < 4; ++r) {
                                                if (diff_Y02[r][0] != 0) active_02++;
                                                if (diff_Y02[r][1] != 0) active_02++;
                                                if (r < 3 && diff_Y02[r][r + 1] != 0) active_02++;
                                                if (diff_Y03[r][0] != 0) active_03++;
                                                if (diff_Y03[r][1] != 0) active_03++;
                                                if (r < 3 && diff_Y03[r][r + 1] != 0) active_03++;
                                            }

                                            // You might need more conditions here to verify the full key
                                            // based on the properties of the cipher and the attack.
                                            // This example uses the same active byte condition as before,
                                            // which might not be sufficient for the full key.
                                            if (active_02 == 2 && active_03 == 2) {
                                                std::cout << "\nPotential full last round key (u7):" << std::endl;
                                                for (int k = 0; k < 16; ++k) {
                                                    std::cout << "Byte " << k << ": 0x" << std::hex << static_cast<int>(u7_full[k]) << std::endl;
                                                }
                                                // You would likely store this potential key or perform further tests.
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
            std::cout << "Exhaustive search for the remaining key bytes complete for this quartet." << std::endl;
        }
    }

    return 0;
}