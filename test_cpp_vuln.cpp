#include <stdio.h>
#include <string.h>

int main() {
    char buf[100];
    gets(buf); // 危険な関数
    strcpy(buf, "test"); // 危険な関数
    char *password = "my_secret_password"; // ハードコード
    char *api_key = "abcdef123456"; // ハードコード
    printf("%s\n", buf);
    return 0;
}
