// SPDX-License-Identifier: GPL-2.0-only
#include <stdio.h>

#include <gwhf/tls/tls.h>

int main(int argc, char *argv[])
{
	gen_key("./ca.key", "./ca.pem");
	return 0;
}
