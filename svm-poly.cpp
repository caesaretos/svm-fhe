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

// utility function read a matrix of doubles
vector<vector<double>> read_2d_matrix_from_file(const string& filename) {
    ifstream file(filename);
    if (!file.is_open()) {
        cout << "Error opening file " << filename << endl;
        return {};
    }

    // Create a vector to store the rows of the 2D matrix.
    vector<vector<double>> matrix;

    // Read each row of the 2D matrix from the file.
    string line;
    while (getline(file, line)) {
        // Split the row into a vector of doubles.
        vector<double> row;
        stringstream ss(line);
        double value;
        while (ss >> value) {
            row.push_back(value);
        }

        // Add the row to the matrix.
        matrix.push_back(row);
    }

    file.close();

    return matrix;
}

void print_matrix(vector<vector<double>> matrix, string label) {
    cout << label << ": [\n";
    for (size_t i = 0; i < matrix.size(); i++) {
        cout << "[";
        for (size_t j = 0; j < matrix[i].size(); j++) {
            cout << setw(15) << setprecision(15) << matrix[i][j] << " ";
        }
        cout << "]" << endl;
    }
    cout << "]" << endl;
}

int main() {

    cout << "SVM Polynomial Kernel started ... !\n\n";

    uint32_t n = 4; // SVM vectors dimensions (# of predictors)
    vector<vector<double>> support_vectors = read_2d_matrix_from_file("../data-kernel-model/support_vectors_poly.txt");
    print_matrix(support_vectors, "support vectors");

    // read the data
    vector<double> dual_coeffs = read_double_data_from_file("../data-kernel-model/dual_coeff_poly.txt");
    vector<double> bias = read_double_data_from_file("../data-kernel-model/intercept_poly.txt");
    resize_double_vector(bias, n);
    vector<double> x = read_double_data_from_file("../data-kernel-model/xtest_poly.txt");
    vector<double> y_ground_truth = read_double_data_from_file("../data-kernel-model/ytest_poly.txt");
    resize_double_vector(y_ground_truth, n);
    vector<double> y_expected_score = read_double_data_from_file("../data-kernel-model/yclassificationscore.txt");
    resize_double_vector(y_expected_score, n);
    
    print_double_vector_comma_separated(dual_coeffs, "dual_coeff");
    print_double_vector_comma_separated(bias, "bias");
    print_double_vector_comma_separated(x, "x");
    print_double_vector_comma_separated(y_ground_truth, "y_ground_truth");
    print_double_vector_comma_separated(y_expected_score, "y_expected_score");

    return 0;

    // Step 1: Setup CryptoContext
    uint32_t multDepth = 2;
    uint32_t scaleModSize = 50;
    uint32_t batchSize = n;
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
    // Plaintext pt_x = cc->MakeCKKSPackedPlaintext(x);
    // Plaintext pt_weights = cc->MakeCKKSPackedPlaintext(weights);
    // Plaintext pt_bias = cc->MakeCKKSPackedPlaintext(bias);

    // cout << "Input pt_x: " << pt_x << endl;
    // cout << "Input pt_weights: " << pt_weights << endl;
    // cout << "Input pt_bias: " << pt_bias << endl;
    

    // // Encrypt the encoded vectors
    // auto ct_x = cc->Encrypt(keys.publicKey, pt_x);
    // auto ct_weights = cc->Encrypt(keys.publicKey, pt_weights);
    // auto ct_bias = cc->Encrypt(keys.publicKey, pt_bias);

    // // Step 4: Evaluation
    // TimeVar t;
    // TIC(t);
    // auto ct_res = cc->EvalInnerProduct(ct_x, ct_weights, n);
    // vector<double> mask = {1.0, 0.0, 0.0, 0.0};
    // Plaintext pt_mask = cc->MakeCKKSPackedPlaintext(mask);
    // ct_res = cc->EvalMult(ct_res, pt_mask);
    // ct_res += ct_bias;
    // auto timeEvalSVMTime = TOC_MS(t);
    // std::cout << "Linear-SVM inference took: " << timeEvalSVMTime << " ms\n\n"; 

    // // Step 5: Decryption and output
    // Plaintext result;
    // // We set the cout precision to 8 decimal digits for a nicer output.
    // // If you want to see the error/noise introduced by CKKS, bump it up
    // // to 15 and it should become visible.
    // cout.precision(8);

    // cout << endl << "Results of homomorphic computations: " << endl;

    // cc->Decrypt(keys.secretKey, ct_res, &result);
    // result->SetLength(batchSize);
    // cout << "computed classification score = " << result;
    // cout << "Estimated precision in bits: " << result->GetLogPrecision() << endl;
    // print_double_vector_comma_separated(y_expected_score, "y_expected_score");

    cout << "SVM Polynomial Kernel terminated gracefully ... !\n";

    return 0;
}