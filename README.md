# Simple SVM Inference in FHE 

This is a sample program that demonstrates how to run SVM inference on encrypted inputs. It is for educational purposes only.

The program uses the OpenFHE library to perform homomorphic encryption, which allows it to perform computations on encrypted data without decrypting it first. The program first loads a pre-trained SVM model and then encrypts the input data. The encrypted data is then passed to the SVM model, which performs inference on the data and returns the predicted class.

The program is a simple example of how SVM inference can be performed on encrypted data. It is not intended for use in production.


## Getting Started

Before you begin, you need to install OpenFHE. OpenFHE is a library for homomorphic encryption, which allows you to perform computations on encrypted data without decrypting it first. Refer to the [OpenFHE](https://github.com/openfheorg/openfhe-development) repo for installation instructions.

To build the project, run the following commands:

```
mkdir build
cd build
cmake ..
make
```