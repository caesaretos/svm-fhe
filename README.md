# Simple SVM Inference with FHE 

This is a sample program that demonstrates how to run SVM inference on encrypted inputs. It is for educational purposes only.

The program uses the OpenFHE library to perform homomorphic encryption, which allows it to perform computations on encrypted data without decrypting it first. The program first loads a pre-trained SVM model and then encrypts the input data. The encrypted data is then passed to the SVM model, which performs inference on the data and returns the predicted class.

This project is a proof-of-concept implementation. It is intended to showcase the algorithm and its potential applications. This project is **not** meant to be used in production environments, and the authors are **not** responsible for any consequences that may arise from doing so.


## Getting Started

Before you begin, you need to install OpenFHE. OpenFHE is a library for homomorphic encryption, which allows you to perform computations on encrypted data without decrypting it first. Refer to the [OpenFHE](https://github.com/openfheorg/openfhe-development) repo for installation instructions.

To build the project, run the following commands:

```
mkdir build
cd build
cmake ..
make
```