/* -*- c -*-
 */
// Copyright (C) 2017 - 2026 Vasily Evseenko <svpcom@p2ptech.org>

/*
 *   This program is free software; you can redistribute it and/or modify
 *   it under the terms of the GNU General Public License as published by
 *   the Free Software Foundation; version 3.
 *
 *   This program is distributed in the hope that it will be useful,
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *   GNU General Public License for more details.
 *
 *   You should have received a copy of the GNU General Public License along
 *   with this program; if not, write to the Free Software Foundation, Inc.,
 *   51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */


#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <sodium.h>
#include <fcntl.h>
#include <unistd.h>

#include <sys/ioctl.h>
#include <linux/random.h>

// A new 0600 inode: a descriptor opened on an old world-readable key file must not read the new key
static int write_key(char *tmp_path, const unsigned char *seckey, const unsigned char *pubkey)
{
    int fd, ok, err;

    if ((fd = mkstemp(tmp_path)) < 0)
    {
        return -1;
    }

    ok = write(fd, seckey, crypto_box_SECRETKEYBYTES) == (ssize_t)crypto_box_SECRETKEYBYTES &&
         write(fd, pubkey, crypto_box_PUBLICKEYBYTES) == (ssize_t)crypto_box_PUBLICKEYBYTES &&
         fsync(fd) == 0;

    if (close(fd) != 0)
    {
        ok = 0;
    }

    if (!ok)
    {
        err = errno;
        unlink(tmp_path);
        errno = err;
        return -1;
    }

    return 0;
}

int main(int argc, char** argv)
{
    unsigned char drone_publickey[crypto_box_PUBLICKEYBYTES];
    unsigned char drone_secretkey[crypto_box_SECRETKEYBYTES];
    unsigned char gs_publickey[crypto_box_PUBLICKEYBYTES];
    unsigned char gs_secretkey[crypto_box_SECRETKEYBYTES];
    char drone_tmp[] = "drone.key.XXXXXX";
    char gs_tmp[] = "gs.key.XXXXXX";
    char *password = NULL;

    if(argc == 2)
    {
        password = argv[1];
    }

    if(argc > 2)
    {
        fprintf(stderr, "Usage: %s [password]\n", argv[0]);
        return 1;
    }

    // check for enough entropy and warn if sodium_init() can freeze
    {
        int fd;
        int c;

        if ((fd = open("/dev/random", O_RDONLY)) != -1)
        {
            if (ioctl(fd, RNDGETENTCNT, &c) == 0 && c < 160)
            {
                fprintf(stderr, "This system doesn't provide enough entropy to quickly generate high-quality random numbers.\n"
                        "Installing the rng-utils/rng-tools, jitterentropy or haveged packages may help.\n"
                        "On virtualized Linux environments, also consider using virtio-rng.\n"
                        "This command will wait until enough entropy has been collected.\n");
            }
            (void) close(fd);
        }
    }

    if (sodium_init() < 0)
    {
        fprintf(stderr, "Libsodium init failed\n");
        return 1;
    }

    if (password != NULL)
    {
        unsigned char salt[crypto_pwhash_argon2i_SALTBYTES] = \
            {'w','i','f','i','b','r','o','a','d','c','a','s','t','k','e','y'};

        unsigned char seed[crypto_box_SEEDBYTES * 2];
        if (crypto_pwhash_argon2i
            (seed, sizeof(seed), password, strlen(password), salt,
             crypto_pwhash_argon2i_OPSLIMIT_INTERACTIVE, // Low CPU usage
             crypto_pwhash_argon2i_MEMLIMIT_INTERACTIVE, // 64MB or RAM is required
             crypto_pwhash_ALG_ARGON2I13) != 0)  // Ensure compatibility with old libsodium versions
        {
            fprintf(stderr, "Unable to derive seed from password\n");
            return 1;
        }
        if (crypto_box_seed_keypair(drone_publickey, drone_secretkey, seed) !=0 ||
            crypto_box_seed_keypair(gs_publickey, gs_secretkey, seed + crypto_box_SEEDBYTES) != 0)
        {
            fprintf(stderr, "Unable to derive keys\n");
            return 1;
        }
        fprintf(stderr, "Keypair derived from provided password\n");
    }
    else
    {
        if (crypto_box_keypair(drone_publickey, drone_secretkey) !=0 ||
            crypto_box_keypair(gs_publickey, gs_secretkey) != 0)
        {
            fprintf(stderr, "Unable to generate keys\n");
            return 1;
        }
        fprintf(stderr, "Keypair generated from random seed\n");
    }

    if (write_key(drone_tmp, drone_secretkey, gs_publickey) != 0)
    {
        perror("Unable to save drone.key");
        return 1;
    }

    if (write_key(gs_tmp, gs_secretkey, drone_publickey) != 0)
    {
        perror("Unable to save gs.key");
        unlink(drone_tmp);
        return 1;
    }

    if (rename(drone_tmp, "drone.key") != 0 || rename(gs_tmp, "gs.key") != 0)
    {
        perror("Unable to save keys");
        unlink(drone_tmp);
        unlink(gs_tmp);
        return 1;
    }

    fprintf(stderr, "Drone keypair (drone sec + gs pub) saved to drone.key\n");
    fprintf(stderr, "GS keypair (gs sec + drone pub) saved to gs.key\n");
    return 0;
}
