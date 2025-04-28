#include <cstdlib>
#include <cstring>
#include <unistd.h>

class N {
public:
    // Constructor
    N(int value) {
        // Set up vtable pointer
        *(void ***)this = &vtable;
        // Store value at offset 104 from start of object
        // (This corresponds to 0x68 in hexadecimal from the original decompiled code)
        *(int *)((char *)this + 104) = value;
    }
    
    // Set annotation method - vulnerability is here!
    void setAnnotation(char *str) {
        size_t len = strlen(str);
        // Copy string starting at offset 4 (right after vtable pointer)
        // No bounds checking! Can overflow the 100-byte buffer
        memcpy((char *)this + 4, str, len);
    }
    
    // operator+ implementation from Ghidra - simplified
    virtual int operator+(N *other) {
        // Access the integer values stored in each object and add them
        int myValue = this->getValue();
        int otherValue = other->getValue();
        return otherValue + myValue;
    }
    
    // Helper method to access the integer value (for readability)
    int getValue() {
        return *(int *)((char *)this + 104);  // Access the value at offset 104
    }
    
private:
    // Object memory layout:
    // Bytes 0-3:   vtable pointer (4 bytes)
    // Bytes 4-103: buffer for annotation (100 bytes)
    // Bytes 104-107: integer value from constructor (4 bytes)
    // Total size: 108 bytes (0x6c in hex)
    
    // This represents the vtable structure
    static void *vtable;
};

int main(int argc, char **argv) {
    // Check for command line argument
    if (argc < 2) {
        _exit(1);
    }
    
    // Create two objects on the heap
    N *obj1 = new N(5);  // 108 bytes
    N *obj2 = new N(6);  // 108 bytes
    
    // Set annotation of first object using command line argument
    obj1->setAnnotation(argv[1]);

    obj2->operator+(obj1);  // obj2 is 'this', obj1 is the parameter 
    return 0;
}