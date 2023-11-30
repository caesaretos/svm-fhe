#define PROFILE

#include "openfhe.h"

using namespace lbcrypto;

#include <iostream>
#include <fstream>
#include <vector>

using namespace std;
// #define VERBOSE

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

    cout << "SVM Sigmoid Kernel v1 started ... !\n\n";

    uint32_t n = 4; // SVM vectors dimensions (# of predictors)
    
    // polynomial kernel parameters
    double gamma = 1.0/n;
    // uint32_t degree = 3;
    vector<vector<double>> support_vectors = read_2d_matrix_from_file("../data-kernel-model-sigmoid/support_vectors_sigmoid.txt");
    std::cout << "number of support vectors: " << support_vectors.size() << "\n";
    std::cout << "dimension of each support vector: " << support_vectors[0].size() << "\n";
    print_matrix(support_vectors, "support vectors");

    // read the data
    vector<double> dual_coeffs = read_double_data_from_file("../data-kernel-model-sigmoid/dual_coeff_sigmoid.txt");
    vector<double> bias = read_double_data_from_file("../data-kernel-model-sigmoid/intercept_sigmoid.txt");
    resize_double_vector(bias, n);
    vector<double> x = read_double_data_from_file("../data-kernel-model-sigmoid/xtest_sigmoid.txt");
    vector<double> y_ground_truth = read_double_data_from_file("../data-kernel-model-sigmoid/ytest_sigmoid.txt");
    resize_double_vector(y_ground_truth, n);
    vector<double> y_expected_score = read_double_data_from_file("../data-kernel-model-sigmoid/yclassificationscore.txt");
    resize_double_vector(y_expected_score, n);
    
    print_double_vector_comma_separated(dual_coeffs, "dual_coeff");
    print_double_vector_comma_separated(bias, "bias");
    print_double_vector_comma_separated(x, "x");
    print_double_vector_comma_separated(y_ground_truth, "y_ground_truth");
    print_double_vector_comma_separated(y_expected_score, "y_expected_score");

    // Step 1: Setup CryptoContext
    uint32_t multDepth = 14; // 11 works
    uint32_t scaleModSize = 59; // 50 works
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
    
    // preparing zero vector for initialization
    vector<double> zeros(n, 0.0);
    Plaintext pt_zeros = cc->MakeCKKSPackedPlaintext(zeros);
    // preparing gamma
    vector<double> gamma_vec(n, 0.0);
    gamma_vec[0] = gamma;
    Plaintext pt_gamma = cc->MakeCKKSPackedPlaintext(gamma_vec);
    
    
    // // prepaing polynomial coeffs
    // vector<double> kernel_poly_coeffs(degree + 1, 0.0);
    // kernel_poly_coeffs[degree] = 1;

    Plaintext pt_x = cc->MakeCKKSPackedPlaintext(x);
    vector<Plaintext> pt_support_vectors;
    for (auto vector : support_vectors) {
        pt_support_vectors.push_back(cc->MakeCKKSPackedPlaintext(vector));
    }
    Plaintext pt_bias = cc->MakeCKKSPackedPlaintext(bias);

    // Encrypt the encoded vectors
    auto ct_x = cc->Encrypt(keys.publicKey, pt_x);
    cout << "num levels in input ctxt: " << ct_x->GetLevel() << "\n";
    cout << "num towers in input ctxt: " << ct_x->GetElements()[0].GetAllElements().size() << endl;
    
    // keep the model un-encrypted
    double lowerBound = -60.0, upperBound = 60.0;
    uint32_t polyDegree = 495; // 13, 27, 59, 119, 247, 495, 1007;

#ifdef VERBOSE
    auto DecAndPrint = [cc, batchSize, keys] (lbcrypto::Ciphertext<lbcrypto::DCRTPoly> ctxt, std::string label)
    {
        Plaintext res;
        // We set the cout precision to 8 decimal digits for a nicer output.
        // If you want to see the error/noise introduced by CKKS, bump it up
        // to 15 and it should become visible.
        cout.precision(8);
        cc->Decrypt(keys.secretKey, ctxt, &res);
        res->SetLength(batchSize);
        cout << label << ": " << res;
        // cout << "Estimated precision in bits: " << res->GetLogPrecision() << endl;
    };
    #else
    auto DecAndPrint = [cc, batchSize, keys] (lbcrypto::Ciphertext<lbcrypto::DCRTPoly> ctxt, std::string label)
    {
        // Plaintext res;
        // // We set the cout precision to 8 decimal digits for a nicer output.
        // // If you want to see the error/noise introduced by CKKS, bump it up
        // // to 15 and it should become visible.
        // cout.precision(8);
        // cc->Decrypt(keys.secretKey, ctxt, &res);
        // res->SetLength(batchSize);
        // cout << label << ": " << res;
        // cout << "Estimated precision in bits: " << res->GetLogPrecision() << endl;
    };
#endif

    // Step 4: Evaluation
    TimeVar t;
    TIC(t);
    // do first vector here
    auto ct_res = cc->Encrypt(keys.publicKey, pt_zeros);
    for (size_t i = 0; i < pt_support_vectors.size(); i++) {
        #ifdef VERBOSE
        cout << "BEGIN BEGIN BEGIN BEGIN BEGIN BEGIN BEGIN BEGIN BEGIN BEGIN BEGIN\n";
        #endif
        std::cout << "iteration: " << i+1 << "\n"; 
        // auto dot_prod = cc->EvalInnerProduct(ct_x, pt_support_vectors[i], n);
        // auto ct_gamma_dot_prod = cc->EvalMult(dot_prod, pt_gamma);
        // auto ct_kernel_out = cc->EvalPoly(ct_gamma_dot_prod, kernel_poly_coeffs);
        // auto ct_out = cc->EvalMult(ct_kernel_out, dual_coeffs[i]);

        auto dot_prod = cc->EvalInnerProduct(ct_x, pt_support_vectors[i], n);
        DecAndPrint(dot_prod, "dot_prod");
        dot_prod = cc->EvalMult(dot_prod, pt_gamma);
        DecAndPrint(dot_prod, "dot_prod*gamma");

        auto ct_out = cc->EvalChebyshevFunction([](double y) -> double { return std::tanh(y); }, dot_prod, lowerBound,
                                        upperBound, polyDegree);
        DecAndPrint(ct_out, "tanh");
        ct_out = cc->EvalMult(ct_out, dual_coeffs[i]);
        ct_res += ct_out;
        #ifdef VERBOSE
        cout << "END END END END END END END END END END END END END END END END END \n";
        #endif
    }
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
    cout << "num levels in result ctxt: " << ct_res->GetLevel() << "\n";
    cout << "num towers in result ctxt: " << ct_res->GetElements()[0].GetAllElements().size() << endl;

    cc->Decrypt(keys.secretKey, ct_res, &result);
    result->SetLength(batchSize);
    cout << "computed classification score = " << result;
    cout << "Estimated precision in bits: " << result->GetLogPrecision() << endl;
    print_double_vector_comma_separated(y_expected_score, "y_expected_score");

    cout << "SVM Sigmoid Kernel terminated gracefully ... !\n";

    return 0;
}