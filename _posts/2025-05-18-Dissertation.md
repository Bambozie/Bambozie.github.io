---
layout: post
title: Dissertation Coding
subtitle: FHE Implementation
categories: [University of Essex]
tags: [University of Essex, Academic Work, unit 28, Dissertation Module]
---
## Client Encrypt
#include "seal/seal.h"
#include <iostream>
#include <fstream>
#include <sstream>
#include <vector>
#include <string>
#include <algorithm>
#include <chrono>
using namespace std;
using namespace seal;


vector<string> parse_csv_line(const string& line) {
    stringstream ss(line);
    string token;
    vector<string> tokens;
    while (getline(ss, token, ',')) tokens.push_back(token);
    return tokens; // CSV parser taken from https://www.studyplan.dev/pro-cpp/string-streams/q/parsing-csv-string-stream
}


string to_lower(const string& s) { // lower case converter
    string result = s;
    transform(result.begin(), result.end(), result.begin(), ::tolower); // taken from https://www.geeksforgeeks.org/how-to-convert-std-string-to-lower-case-in-cpp/
    return result;
}

int main() {
    auto start = chrono::high_resolution_clock::now();
    //CKKS encryption setup
    EncryptionParameters parms(scheme_type::ckks);
    size_t poly_modulus_degree = 8192;
    parms.set_poly_modulus_degree(poly_modulus_degree);
    parms.set_coeff_modulus(CoeffModulus::Create(poly_modulus_degree, { 40, 40, 40 }));
    SEALContext context(parms);
    cout << "Client encrypt: initialized SEAL context with CKKS.\n";

    
    KeyGenerator keygen(context); // key generation we are using 1) Public key to be used on the cloud process side 2) secret key for encryption and decryption 3) galois keys for slot rotation to rotate the value of BPMs
    auto secret_key = keygen.secret_key();
    PublicKey public_key;
    GaloisKeys galois_keys;
    //RelinKeys relin_keys;
    keygen.create_public_key(public_key);
    keygen.create_galois_keys(galois_keys);
    //keygen.create_relin_keys(relin_keys);

    Encryptor encryptor(context, public_key);
    CKKSEncoder encoder(context);

    double scale = pow(2.0, 40);
    size_t slot_count = encoder.slot_count(); // this totals the slots for BPM values to 4096 which is half of the poly_modulus_degree if we want to create the count we must increase this value in all 3 programs

    
    ifstream file("E:\\Dissertation Coding\\mimic-iii-clinical-database-demo-1.4\\CHARTEVENTS.csv"); // To load the BPM data from the chartevents found in the mimic-3 database https://physionet.org/content/mimiciii-demo/1.4/
    string line;
    getline(file, line);

    vector<double> heart_rates;
    size_t count = 0;

    while (getline(file, line)) {
        auto cols = parse_csv_line(line);
        if (cols.size() >= 11) {
            try {
                string valueuom = to_lower(cols[10]); 
                if (valueuom == "bpm") { //to parse the valueuom field found in the chartevents.csv we used bpm only for simulation purposes
                    double bpm = stod(cols[9]);
                    if (bpm > 0 && bpm < 300) {
                        heart_rates.push_back(bpm);
                        ++count;
                    }
                }
            }
            catch (...) {}
        }
        if (heart_rates.size() >= slot_count) break;
    }
    file.close();

    
    //heart_rates.resize(slot_count, 0.0); this will pad remaining slots but generally unused because the data in chartevents are much larger than the slot count that will be occupied this was used in the beginning iterations when i was testing only a couple of fields to ensure result accuarcy

    
    Plaintext plain;
    encoder.encode(heart_rates, scale, plain); //data must be encoded before encryption
    Ciphertext encrypted;
    encryptor.encrypt(plain, encrypted);

    auto end = chrono::high_resolution_clock::now();
    auto duration = chrono::duration_cast<chrono::milliseconds>(end - start).count();
    cout << "Benchmark no encryption processing took " << duration << " ms.\n";

    // To save the files & keys in the directory below
    ofstream ctxt("E:\\Dissertation Coding\\Public Gal Key & Encrypted Data\\encrypted.ctxt", ios::binary); encrypted.save(ctxt); ctxt.close();
    ofstream pk("E:\\Dissertation Coding\\Public Gal Key & Encrypted Data\\public.key", ios::binary); public_key.save(pk); pk.close();
    ofstream sk("E:\\Dissertation Coding\\Secret Key\\secret.key", ios::binary); secret_key.save(sk); sk.close();
    ofstream gk("E:\\Dissertation Coding\\Public Gal Key & Encrypted Data\\galois.keys", ios::binary); galois_keys.save(gk); gk.close();
    //ofstream rk("E:\\Dissertation Coding\\Public Gal Key & Encrypted Data\\relin.keys", ios::binary); relin_keys.save(rk); rk.close(); note we are no longer using relin keys they were a test to perform multiplication and they were needed then.

    ofstream count_file("E:\\Dissertation Coding\\Public Gal Key & Encrypted Data\\valid_count.txt"); // To save the slot count in our case its 4096 which is half of the poly_modulus_degree (8192), this was added to change the number of slots and then divide them dynamically later on.
    count_file << count;
    count_file.close();

    cout << "Client: Encrypted " << count << " BPM values (out of " << slot_count << " slots). All data saved.\n";
    return 0;
}


## Cloud Process

#include "seal/seal.h"
#include <iostream>
#include <fstream>
#include <chrono> 

using namespace std;
using namespace seal;

int main() {
    try {
        auto start = chrono::high_resolution_clock::now();
        // FHE setup using CKKS encryption parameters
        EncryptionParameters parms(scheme_type::ckks);
        size_t poly_modulus_degree = 8192;
        parms.set_poly_modulus_degree(poly_modulus_degree);
        parms.set_coeff_modulus(CoeffModulus::Create(poly_modulus_degree, { 40, 40, 40 }));

        SEALContext context(parms);
        cout << "Cloud: Initialized SEAL context.\n";

       
        Ciphertext encrypted;
        ifstream ctxt_file("E:\\Dissertation Coding\\Public Gal Key & Encrypted Data\\encrypted.ctxt", ios::binary); //we are loading the encrypted file which is one of the outputs of the client encrypt
        if (!ctxt_file.is_open()) {
            cerr << "Could not open encrypted.ctxt file.\n";
            return 1;
        }
        encrypted.load(context, ctxt_file);
        ctxt_file.close();

        // we are using Galois keys to help calculate the average they allow you to rotate values in the slots to add them together so we can eventually divide by their Number on the client decryptor side (they must also be generated in the client encrypt file)
        GaloisKeys galois_keys;
        ifstream gk_file("E:\\Dissertation Coding\\Public Gal Key & Encrypted Data\\galois.keys", ios::binary);
        if (!gk_file.is_open()) {
            cerr << "Could not open galois.keys file.\n";
            return 1;
        }
        galois_keys.load(context, gk_file);
        gk_file.close();

        Evaluator evaluator(context); // The Evaluator allows us to perform mathematical operations on encrypted data 
        CKKSEncoder encoder(context); // calculating the average requires use of floating points the encoder allows us to run operations on floating points
        size_t slot_count = encoder.slot_count();

       
        Ciphertext sum = encrypted;
        for (size_t i = 1; i < slot_count; i <<= 1) {
            Ciphertext rotated;
            evaluator.rotate_vector(sum, i, galois_keys, rotated); //rotates and adds the next value
            evaluator.add_inplace(sum, rotated);
        }


        
        ofstream result_file("E:\\Dissertation Coding\\Processed File\\summed.ctxt", ios::binary); // saving the result on a ctxt file we used ctxt to distinguish it from normal plain text files however this does not matter it could be saved as a txt file.
        if (!result_file.is_open()) {
            cerr << "Could not save summed.ctxt file.\n";
            return 1;
        }
        sum.save(result_file);
        result_file.close();
        auto end = chrono::high_resolution_clock::now();
        auto duration = chrono::duration_cast<chrono::milliseconds>(end - start).count();
        cout << "Cloud: Homomorphic processing took " << duration << " ms.\n";

        cout << "Cloud: Encrypted summation complete.\n";
        return 0;

    }
    catch (const exception& e) {
        cerr << "Exception: " << e.what() << endl;
        return 1;
    }
}
// some code snippets have been taken from https://github.com/microsoft/SEAL/blob/main/native/examples/5_ckks_basics.cpp

## Client Decrypt

#include "seal/seal.h"
#include <iostream>
#include <fstream>
#include <vector>
#include <string>

using namespace std;
using namespace seal;

int main() {
    EncryptionParameters parms(scheme_type::ckks); //CKKS encryption parameters
    size_t poly_modulus_degree = 8192;
    parms.set_poly_modulus_degree(poly_modulus_degree);
    parms.set_coeff_modulus(CoeffModulus::Create(poly_modulus_degree, { 40, 40, 40 }));

    SEALContext context(parms);
    cout << "Client: SEAL context initialized.\n";

    
    SecretKey secret_key;
    ifstream sk("E:\\Dissertation Coding\\Secret Key\\secret.key", ios::binary); //secret key generated from client encrypt
    if (!sk.is_open()) {
        cerr << "Failed to open secret.key.\n";
        return 1;
    }
    secret_key.load(context, sk);
    sk.close();

    
    Ciphertext encrypted_sum;
    ifstream in("E:\\Dissertation Coding\\Processed File\\summed.ctxt", ios::binary); //loads the sum of data calculated on the cloud process
    if (!in.is_open()) {
        cerr << "Failed to open summed.ctxt.\n";
        return 1;
    }
    encrypted_sum.load(context, in);
    in.close();

   
    size_t valid_count = 0;
    ifstream count_file("E:\\Dissertation Coding\\Public Gal Key & Encrypted Data\\valid_count.txt"); //loads the slot count saved from client encrypt to divide the summed value
    if (!count_file.is_open()) {
        cerr << "Failed to open valid_count.txt.\n";
        return 1;
    }
    count_file >> valid_count;
    count_file.close();

    if (valid_count == 0) {
        cerr << "No valid BPM values recorded.\n";
        return 1;
    }

    
    Decryptor decryptor(context, secret_key);
    CKKSEncoder encoder(context);
    Plaintext plain_result;
    decryptor.decrypt(encrypted_sum, plain_result);

    vector<double> decoded;
    encoder.decode(plain_result, decoded);

    
    double total = decoded[0];
    double average = total / static_cast<double>(valid_count);  //calculating the average using the slot count and summed values

    cout << "Client: Decrypted average heart rate = " << average << " bpm (approx).\n";

    
    ofstream csv("E:\\Dissertation Coding\\Results\\decrypted_average.csv"); // to save the output in a csv file
    if (csv.is_open()) {
        csv << "average\n" << average << endl;
        csv.close();
        cout << "Client: Average saved to decrypted_average.csv\n";
    }
    else {
        cerr << "Failed to write CSV output.\n";
        return 1;
    }

    return 0;
}

## Benchmark code

#include <iostream>
#include <fstream>
#include <sstream>
#include <vector>
#include <string>
#include <algorithm>
#include <chrono>

using namespace std;

vector<string> parse_csv_line(const string& line) {
    stringstream ss(line);
    string token;
    vector<string> tokens;
    while (getline(ss, token, ',')) {
        tokens.push_back(token);
    }
    return tokens;
}
string to_lower(const string& s) {
    string result = s;
    transform(result.begin(), result.end(), result.begin(), ::tolower);
    return result;
}

int main() {
    const size_t limit = 4096;
    vector<double> bpm_values;

    auto start = chrono::high_resolution_clock::now();

    ifstream file("E:\\Dissertation Coding\\mimic-iii-clinical-database-demo-1.4\\CHARTEVENTS.csv");
    if (!file.is_open()) {
        cerr << "Error opening CHARTEVENTS.csv file.\n";
        return 1;
    }

    string line;
    getline(file, line);

    while (getline(file, line)) {
        auto cols = parse_csv_line(line);
        if (cols.size() >= 11) {
            try {
                string valueuom = to_lower(cols[10]);
                if (valueuom == "bpm") {
                    double bpm = stod(cols[9]);
                    if (bpm > 0 && bpm < 300) {
                        bpm_values.push_back(bpm);
                    }
                }
            }
            catch (...) {
                continue;
            }
        }
        if (bpm_values.size() >= limit) break;
    }

    file.close();

    if (bpm_values.empty()) {
        cout << "No valid BPM data found.\n";
        return 1;
    }

    double sum = 0;
    for (double bpm : bpm_values) {
        sum += bpm;
    }
    double average = sum / bpm_values.size();

    auto end = chrono::high_resolution_clock::now();
    auto duration = chrono::duration_cast<chrono::milliseconds>(end - start).count();
    cout << "Benchmark no encryption processing took " << duration << " ms.\n";
    cout << "Average BPM (first " << bpm_values.size() << " values): " << average << " bpm\n";
 

    return 0;
}
