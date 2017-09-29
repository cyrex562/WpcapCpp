#include <cstdint>
#include <cstdlib>


typedef struct Hat {
    int num_elements;
    void* top = NULL;
    int top_used = 0;

};

void initHat(const size_t expected_size, Hat* hat) {
    setPower(recommendedPower(expected_size));
    hat->num_elements;
    hat->top = NULL;
    hat->top_used = 0;
}

void cleanupHat(Hat* hat) {
    for (size_t i = 0; i < hat->top_used; i++) {
        free(hat->top[i]);
    }
}