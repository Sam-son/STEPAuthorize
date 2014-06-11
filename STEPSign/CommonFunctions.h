#pragma once

#include <openssl/pem.h>
#include <openssl/conf.h>
#include <openssl/err.h>

void initialize();
void clean_up();