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

// cloning a vector m-1 times, and appending the clones to its end
void clone_vector_inplace(vector<double>& vector, int m) {
    auto orig = vector;
    for (int i = 0; i < m - 1; i++) {
        vector.insert(vector.end(), orig.begin(), orig.end());
    }
}

vector<double> flatten_vector(vector<vector<double>> vector_of_vectors) {
    // Create a vector to store the flattened vector
    vector<double> flattened_vector;

    // Iterate over the vector of vectors
    for (vector<double> vector : vector_of_vectors) {
        // Append the vector to the flattened vector
        flattened_vector.insert(flattened_vector.end(), vector.begin(), vector.end());
    }

    // Return the flattened vector
    return flattened_vector;
}

int next_power_of_2(int number) {
    // Check if the number is already a power of 2
    if ((number & (number - 1)) == 0) {
        return number;
    }

    // Find the next power of 2
    int next_power_of_2 = 1;
    while (next_power_of_2 < number) {
        next_power_of_2 *= 2;
    }

    // Return the next power of 2
    return next_power_of_2;
}

const string DATA_FOLDER = "../data-kernel-model/";

int main() {

    cout << "SVM Polynomial Kernel started ... !\n\n";

    uint32_t n = 4; // SVM vectors dimensions (# of predictors)
    
    // polynomial kernel parameters
    double gamma = 2;
    uint32_t degree = 3;
    vector<vector<double>> support_vectors = read_2d_matrix_from_file(DATA_FOLDER + "support_vectors_poly.txt");
    uint32_t n_SVs = support_vectors.size();
    std::cout << "number of support vectors: " << n_SVs << "\n";
    std::cout << "dimension of each support vector: " << support_vectors[0].size() << "\n";
    print_matrix(support_vectors, "support vectors");

    // read the data
    vector<double> dual_coeffs = read_double_data_from_file(DATA_FOLDER + "dual_coeff_poly.txt");
    vector<double> bias = read_double_data_from_file(DATA_FOLDER + "intercept_poly.txt");
    resize_double_vector(bias, n);
    vector<double> x = read_double_data_from_file(DATA_FOLDER + "xtest_poly.txt");
    vector<double> y_ground_truth = read_double_data_from_file(DATA_FOLDER + "ytest_poly.txt");
    resize_double_vector(y_ground_truth, n);
    vector<double> y_expected_score = read_double_data_from_file(DATA_FOLDER + "yclassificationscore.txt");
    resize_double_vector(y_expected_score, n);
    
    print_double_vector_comma_separated(dual_coeffs, "dual_coeff");
    print_double_vector_comma_separated(bias, "bias");
    print_double_vector_comma_separated(x, "x");
    print_double_vector_comma_separated(y_ground_truth, "y_ground_truth");
    print_double_vector_comma_separated(y_expected_score, "y_expected_score");

    // Step 1: Setup CryptoContext
    uint32_t multDepth = 6;
    uint32_t scaleModSize = 50;
    uint32_t batchSize = n;
    CCParams<CryptoContextCKKSRNS> parameters;
    parameters.SetMultiplicativeDepth(multDepth);
    parameters.SetScalingModSize(scaleModSize);
    parameters.SetBatchSize(next_power_of_2(batchSize*n_SVs));
    parameters.SetScalingTechnique(FIXEDAUTO);
    parameters.SetSecurityLevel(HEStd_NotSet); 
    parameters.SetRingDim(128*2);

    CryptoContext<DCRTPoly> cc = GenCryptoContext(parameters);

    // Enable the features that you wish to use
    cc->Enable(PKE);
    cc->Enable(KEYSWITCH);
    cc->Enable(LEVELEDSHE);
    cc->Enable(ADVANCEDSHE);
    cout << "CKKS scheme is using ring dimension " << cc->GetRingDimension() << endl << endl;

    // Step 2: Key Generation
    auto keys = cc->KeyGen();

    std::cout << "Key gen started\n";
    cc->EvalMultKeyGen(keys.secretKey);
    cc->EvalSumKeyGen(keys.secretKey);
    auto evalSumColKeys = cc->EvalSumColsKeyGen(keys.secretKey);
    std::cout << "Key gen done\n";

    auto decrypt_and_print = [&](Ciphertext<DCRTPoly> &ct, const string& label) {
        Plaintext res;
        cout.precision(8);

        cout << endl << label << ": " << endl;
        cc->Decrypt(keys.secretKey, ct, &res);
        res->SetLength(next_power_of_2(batchSize*n_SVs));
        cout << res;
    };

    // Step 3: Encoding and encryption of inputs
  
    // preparing gamma
    vector<double> gamma_vec(n, 0.0);
    gamma_vec[0] = gamma;
    std::cout << "n: " << n << "\n";
    clone_vector_inplace(gamma_vec, n_SVs);
    gamma_vec.resize(next_power_of_2(n*n_SVs), 0);
    std::cout << "gamma_vec.size: " << gamma_vec.size() << "\n";
    Plaintext pt_gamma = cc->MakeCKKSPackedPlaintext(gamma_vec);
    std::cout << "encoding gamma done\n";
    
    // preparing polynomial coeffs
    vector<double> kernel_poly_coeffs(degree + 1, 0.0);
    kernel_poly_coeffs[degree] = 1;

    // clone x, as many as support vectors
    clone_vector_inplace(x, n_SVs);
    x.resize(next_power_of_2(n*n_SVs), 0);
    Plaintext pt_x = cc->MakeCKKSPackedPlaintext(x);
    std::cout << "encoding cloned x done\n";
    // support vectors in 1 plaintext (flattend)
    vector<double> flattened_support_vectors = flatten_vector(support_vectors);
    flattened_support_vectors.resize(next_power_of_2(n*n_SVs), 0);
    Plaintext pt_support_vectors = cc->MakeCKKSPackedPlaintext(flattened_support_vectors);
    std::cout << "encoding flattend support vectors done\n";
    // bias
    bias.resize(next_power_of_2(n*n_SVs), 0);
    Plaintext pt_bias = cc->MakeCKKSPackedPlaintext(bias);
    std::cout << "encoding bias done\n";
    // dual coeffs
    vector<double> dual_coeffs_vec(n*n_SVs, 0.0);
    for(size_t i = 0; i < dual_coeffs.size(); i++) {
        dual_coeffs_vec[i*n] = dual_coeffs[i];
    }
    Plaintext pt_dual_coeffs = cc->MakeCKKSPackedPlaintext(dual_coeffs_vec);
    std::cout << "data encoding done\n";

    // Encrypt the encoded vectors
    std::cout << "encrypting x\n";
    auto ct_x = cc->Encrypt(keys.publicKey, pt_x);
    
    // keep the model un-encrypted

    // Step 4: Evaluation
    std::cout << "evaluation started ... \n\n";
    TimeVar t;
    TIC(t);
    // do first vector here
    decrypt_and_print(ct_x, "ct_x");
    auto ct_prod = cc->EvalMult(ct_x, pt_support_vectors);
    decrypt_and_print(ct_prod, "ct_prod");
    std::cout << "Mult Done 1\n";
    auto ct_dot_prod = cc->EvalSumCols(ct_prod, n, *evalSumColKeys);
    decrypt_and_print(ct_dot_prod, "ct_dot_prod");
    std::cout << "2\n";
    auto ct_gamma_dot_prod = cc->EvalMult(ct_dot_prod, pt_gamma);
    decrypt_and_print(ct_gamma_dot_prod, "ct_gamma_dot_prod");
    std::cout << "3\nevaluating PS\n";
    print_double_vector_comma_separated(kernel_poly_coeffs, "kernel");
    auto tmp = cc->EvalSquare(ct_gamma_dot_prod);
    auto ct_kernel_out = cc->EvalMult(ct_gamma_dot_prod, tmp);
    
    // auto ct_kernel_out = cc->EvalPolyPS(ct_gamma_dot_prod, kernel_poly_coeffs);
    
    decrypt_and_print(ct_kernel_out, "ct_kernel_out");
    std::cout << "4\n";
    auto ct_kernel_dual_coeffs = cc->EvalMult(ct_kernel_out, pt_dual_coeffs);
    decrypt_and_print(ct_kernel_dual_coeffs, "ct_kernel_dual_coeffs");
    std::cout << "5\n";
    auto ct_sum = cc->EvalSum(ct_kernel_dual_coeffs, next_power_of_2(n*n_SVs));
    decrypt_and_print(ct_sum, "ct_sum");
    std::cout << "6\n";
    auto ct_res = cc->EvalAdd(ct_sum, pt_bias);
    decrypt_and_print(ct_res, "ct_res");
    std::cout << "7\n";
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

    cout << "SVM Polynomial Kernel terminated gracefully ... !\n";

    return 0;
}