#define _CRT_SECURE_NO_WARNINGS //so our program can run with these buffer overflows
#include <iostream>
#include <cstring>

// Function that contains the vulnerable authentication logic
int performAuthentication(const char* username, const char* password) {
    int authentication = 0;
    char cUsername[10];
    char cPassword[10];

    // Potentially vulnerable strcpy operations (no bounds checking)
    strcpy(cUsername, username);
    strcpy(cPassword, password);

    // Check credentials
    if (strcmp(cUsername, "admin") == 0 && strcmp(cPassword, "adminpass") == 0) {
        authentication = 1;
    }

    return authentication;
}

// Function to display interactive authentication prompt
void runInteractiveAuth() {
    char inputUsername[100]; // Larger buffer for user input
    char inputPassword[100]; // Larger buffer for user input

    std::cout << "Username: ";
    std::cin >> inputUsername;

    std::cout << "Pass: ";
    std::cin >> inputPassword;

    // Call the vulnerable function
    int result = performAuthentication(inputUsername, inputPassword);

    // Display result
    if (result) {
        std::cout << "Access granted\n";
        std::cout << static_cast<char>(result);
    }
    else {
        std::cout << "Wrong username and password\n";
    }
}

// This allows the test to be compiled as a standalone executable
// but also used as a component in other programs
#ifdef STANDALONE_TEST
int main(void) {
    runInteractiveAuth();
    return 0;
}
#endif

// API function that can be called from the main application
extern "C" {
    // Function that BinaryRipper can call to test with specific inputs
    __declspec(dllexport) int testAuthentication(const char* username, const char* password) {
        return performAuthentication(username, password);
    }

    // Function that BinaryRipper can call to run the interactive version
    __declspec(dllexport) void runAuthTest() {
        runInteractiveAuth();
    }
}