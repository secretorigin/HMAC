#include <iostream>
#include <stdexcept>



int main() {
  try {
    // your functions and tests here
    // ...

  } catch(const std::exception& excpt) {
    std::cout << excpt.what() << "\n";
  }

	return 0;
}