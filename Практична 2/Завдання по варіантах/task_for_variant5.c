#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <math.h>
#include <stdbool.h>

#define STACK_SIZE 100
#define VARS_COUNT ('z' - 'a' + 1)

typedef struct {
    double data[STACK_SIZE];
    int top;
} Stack;

typedef struct {
    char name;
    double value;
    bool initialized;
} Variable;

void initStack(Stack *s) {
    s->top = -1;
}

bool isEmpty(Stack *s) {
    return s->top == -1;
}

bool isFull(Stack *s) {
    return s->top == STACK_SIZE - 1;
}

bool push(Stack *s, double value) {
    if (isFull(s)) {
        fprintf(stderr, "Stack overflow!\n");
        return false;
    }
    s->data[++(s->top)] = value;
    return true;
}

bool pop(Stack *s, double *value) {
    if (isEmpty(s)) {
        fprintf(stderr, "Stack underflow!\n");
        return false;
    }
    *value = s->data[(s->top)--];
    return true;
}

bool peek(Stack *s, double *value) {
    if (isEmpty(s)) {
        fprintf(stderr, "Stack is empty!\n");
        return false;
    }
    *value = s->data[s->top];
    return true;
}

bool performOperation(Stack *s, char op) {
    double a, b;
    if (!pop(s, &b) || !pop(s, &a)) return false;

    double result;
    switch (op) {
        case '+': result = a + b; break;
        case '-': result = a - b; break;
        case '*': result = a * b; break;
        case '/': 
            if (b == 0) {
                fprintf(stderr, "Division by zero!\n");
                return false;
            }
            result = a / b;
            break;
        case '^': result = pow(a, b); break;
        default:
            fprintf(stderr, "Unknown operator: %c\n", op);
            return false;
    }
    return push(s, result);
}

void initVariables(Variable *vars) {
    for (int i = 0; i < VARS_COUNT; ++i) {
        vars[i].name = 'a' + i;
        vars[i].initialized = false;
    }
}

bool assignVariable(Variable *vars, char var, double value) {
    if (var < 'a' || var > 'z') {
        fprintf(stderr, "Invalid variable name. Use a-z.\n");
        return false;
    }
    vars[var - 'a'].value = value;
    vars[var - 'a'].initialized = true;
    return true;
}

bool getVariableValue(Variable *vars, char var, double *value) {
    if (var < 'a' || var > 'z' || !vars[var - 'a'].initialized) {
        fprintf(stderr, "Variable '%c' not initialized.\n", var);
        return false;
    }
    *value = vars[var - 'a'].value;
    return true;
}

void evaluateExpression(const char *expr) {
    Stack s;
    initStack(&s);
    Variable vars[VARS_COUNT];
    initVariables(vars);

    char *token = strtok((char*)expr, " ");
    while (token != NULL) {
        if (isdigit(token[0]) || (token[0] == '-' && isdigit(token[1]))) {
            push(&s, atof(token));
        } 
        else if (strlen(token) == 1 && strchr("+-*/^", token[0])) {
            if (!performOperation(&s, token[0])) return;
        } 
        else if (token[0] == '=' && isalpha(token[1])) {
            double value;
            if (!pop(&s, &value)) return;
            assignVariable(vars, token[1], value);
        } 
        else if (isalpha(token[0])) {
            double value;
            if (!getVariableValue(vars, token[0], &value)) return;
            push(&s, value);
        } 
        else {
            fprintf(stderr, "Invalid token: %s\n", token);
            return;
        }
        token = strtok(NULL, " ");
    }

    double result;
    if (pop(&s, &result) && isEmpty(&s)) {
        printf("Result: %g\n", result);
    } else {
        fprintf(stderr, "Error: Invalid expression\n");
    }
}

int main() {
    char expr[256];
    printf("Enter RPN expression (e.g., '5 3 + =x x 2 *'): ");
    if (!fgets(expr, sizeof(expr), stdin)) {
        fprintf(stderr, "Input error\n");
        return 1;
    }
    expr[strcspn(expr, "\n")] = '\0';

    evaluateExpression(expr);
    return 0;
}

