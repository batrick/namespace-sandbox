sandbox: sandbox.c
	$(CC) -g -o $@ $< -lseccomp

# vim: set noexpandtab tabstop=4:
