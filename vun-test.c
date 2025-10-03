#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

void buffer_overflow() {
    char buffer[32];
    printf("Enter your name: ");
    gets(buffer);  // Vulnerable function (buffer overflow)
    printf("Hello, %s!\n", buffer);
}

void format_string() {
    char input[100];
    printf("Enter a message: ");
    scanf("%99s", input);
    printf(input);  // Vulnerable to format string attack
    printf("\n");
}

void command_injection() {
    char command[50];
    printf("Enter a command: ");
    scanf("%49s", command);
    system(command);  // Vulnerable to command injection
}

void integer_overflow() {
    unsigned int num1, num2;
    printf("Enter two numbers: ");
    scanf("%u %u", &num1, &num2);
    unsigned int result = num1 + num2;  // Possible integer overflow
    printf("Result: %u\n", result);
}

int main() {
    int choice;
    
    while (1) {
        printf("\nVulnerable C Program\n");
        printf("1. Buffer Overflow\n");
        printf("2. Format String\n");
        printf("3. Command Injection\n");
        printf("4. Integer Overflow\n");
        printf("5. Exit\n");
        printf("Choose an option: ");
        scanf("%d", &choice);
        getchar();  // Clear input buffer
        
        switch (choice) {
            case 1: buffer_overflow(); break;
            case 2: format_string(); break;
            case 3: command_injection(); break;
            case 4: integer_overflow(); break;
            case 5: exit(0);
            default: printf("Invalid choice\n");
        }
    }

    return 0;
}
