#define PROFILE

#include "openfhe.h"

using namespace lbcrypto;

#include <iostream>
#include <fstream>
#include <vector>

using namespace std;

// utility functions
void print_double_vector_comma_separated(const vector<double>& data, const string& label) {
    cout << label << ": [";
    for (size_t i = 0; i < data.size() - 1; i++) {
        cout << setprecision(15) << data[i] << ", ";
    }
    cout << setprecision(15) << data[data.size() - 1] << "]" << endl;
}

// utility function to read a vector of doubles
vector<double> read_double_data_from_file(const string& filename) {
    vector<double> data;
    ifstream in(filename);
    if (!in) {
        cerr << "Could not open file " << filename << endl;
        return data;
    }

    double number;
    while (in >> number) {
        data.push_back(number);
    }

    // Close the file
    in.close();

    return data;
}

void resize_double_vector(vector<double>& data, uint32_t new_size) {
    // If the new size is smaller than the current size,
    // we need to shorten the vector.
    if (new_size < data.size()) {
        data.resize(new_size);
    } else {
        // If the new size is larger than the current size,
        // we need to add new entries and zero them out.
        for (size_t i = data.size(); i < new_size; i++) {
            data.push_back(0.0);
        }
    }
}


int main() {

    cout << "SVM linear started ... !\n\n";

    uint32_t n = 30; // SVM vectors dimensions (# of predictors)

    // read the data
    vector<double> weights = read_double_data_from_file("../data-linear-model/weights.txt");
    vector<double> bias = read_double_data_from_file("../data-linear-model/bias.txt");
    resize_double_vector(bias, n);
    vector<double> x = read_double_data_from_file("../data-linear-model/xtest.txt");
    vector<double> y_ground_truth = read_double_data_from_file("../data-linear-model/ytest.txt");
    resize_double_vector(y_ground_truth, n);
    vector<double> y_expected_score = read_double_data_from_file("../data-linear-model/yclassificationscore.txt");
    resize_double_vector(y_expected_score, n);
    
    print_double_vector_comma_separated(weights, "weights");
    print_double_vector_comma_separated(bias, "bias");
    print_double_vector_comma_separated(x, "x");
    print_double_vector_comma_separated(y_ground_truth, "y_ground_truth");
    print_double_vector_comma_separated(y_expected_score, "y_expected_score");

    #if NATIVEINT == 128
    std::cout << "Using 128-bit OpenFHE" << std::endl;
    #else
    std::cout << "Using 64-bit OpenFHE" << std::endl;
    #endif

    // Step 1: Setup CryptoContext
    uint32_t multDepth = 2;
    uint32_t scaleModSize = 50;
    uint32_t batchSize = 32; // next power of 2 of n
    CCParams<CryptoContextCKKSRNS> parameters;
    parameters.SetMultiplicativeDepth(multDepth);
    parameters.SetScalingModSize(scaleModSize);
    parameters.SetBatchSize(batchSize);

    CryptoContext<DCRTPoly> cc = GenCryptoContext(parameters);

    // Enable the features that you wish to use
    cc->Enable(PKE);
    cc->Enable(KEYSWITCH);
    cc->Enable(LEVELEDSHE);
    cc->Enable(ADVANCEDSHE);
    cout << "CKKS scheme is using ring dimension " << cc->GetRingDimension() << endl << endl;

    // Step 2: Key Generation
    auto keys = cc->KeyGen();

    cc->EvalMultKeyGen(keys.secretKey);
    cc->EvalSumKeyGen(keys.secretKey);

    // Step 3: Encoding and encryption of inputs

    // Encoding as plaintexts
    Plaintext pt_x = cc->MakeCKKSPackedPlaintext(x);
    Plaintext pt_weights = cc->MakeCKKSPackedPlaintext(weights);
    Plaintext pt_bias = cc->MakeCKKSPackedPlaintext(bias);

    cout << "Input pt_x: " << pt_x << endl;
    cout << "Input pt_weights: " << pt_weights << endl;
    cout << "Input pt_bias: " << pt_bias << endl;
    

    // Encrypt the encoded vectors
    auto ct_x = cc->Encrypt(keys.publicKey, pt_x);

    // Step 4: Evaluation
    TimeVar t;
    TIC(t);
    auto ct_res = cc->EvalInnerProduct(ct_x, pt_weights, n);
    vector<double> mask(n, 0.0);
    mask[0] = 1.0;
    Plaintext pt_mask = cc->MakeCKKSPackedPlaintext(mask);
    ct_res = cc->EvalMult(ct_res, pt_mask);
    ct_res = cc->EvalAdd(ct_res, pt_bias);
    auto timeEvalSVMTime = TOC_MS(t);
    std::cout << "Linear-SVM inference took: " << timeEvalSVMTime << " ms\n\n"; 

    // Step 5: Decryption and output
    Plaintext result;
    // We set the cout precision to 8 decimal digits for a nicer output.
    // If you want to see the error/noise introduced by CKKS, bump it up
    // to 15 and it should become visible.
    cout.precision(8);

    cout << endl << "Results of homomorphic computations: " << endl;

    cc->Decrypt(keys.secretKey, ct_res, &result);
    result->SetLength(batchSize);
    cout << "computed classification score = " << result;
    cout << "Estimated precision in bits: " << result->GetLogPrecision() << endl;
    print_double_vector_comma_separated(y_expected_score, "y_expected_score");

    cout << "SVM linear terminated gracefully ... !\n";

    return 0;
}