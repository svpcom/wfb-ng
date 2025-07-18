/*
 * Copyright (C) 2008 Wim Taymans <wim.taymans at gmail.com>
 * Copyright (C) 2025 Vasily Evseenko <svpcom@p2ptech.org>

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
#include <gst/gst.h>
#include <gst/rtsp-server/rtsp-server.h>

/* this timeout is periodically run to clean up the expired sessions from the
 * pool. This needs to be run explicitly currently but might be done
 * automatically as part of the mainloop. */

static gboolean
timeout (GstRTSPServer * server)
{
    GstRTSPSessionPool *pool;

    pool = gst_rtsp_server_get_session_pool (server);
    gst_rtsp_session_pool_cleanup (pool);
    g_object_unref (pool);

    return TRUE;
}

int
main (int argc, char *argv[])
{
    GMainLoop *loop;
    GstRTSPServer *server;
    GstRTSPMountPoints *mounts;
    GstRTSPMediaFactory *factory;
    int mode;
    char buf[2048];
    int mtu = 1400;

    gst_init (&argc, &argv);

    if(argc < 2 || (strcmp(argv[1], "h264") != 0 && strcmp(argv[1], "h265") != 0))
    {
        fprintf(stderr, "Usage: %s { h264 | h265 } [mtu]\n", argv[0]);
        fprintf(stderr, "WFB-ng version %s\n", WFB_VERSION);
        fprintf(stderr, "WFB-ng home page: <http://wfb-ng.org>\n");
        exit(1);
    }

    if(argc == 3)
    {
        mtu = atoi(argv[2]);
    }

    mode = atoi(argv[1] + 1);
    loop = g_main_loop_new (NULL, FALSE);

    /* create a server instance */
    server = gst_rtsp_server_new ();

    /* get the mount points for this server, every server has a default object
     * that be used to map uri mount points to media factories */
    mounts = gst_rtsp_server_get_mount_points (server);

    /* make a media factory for a test stream. The default media factory can use
     * gst-launch syntax to create pipelines.
     * any launch line works as long as it contains elements named pay%d. Each
     * element with pay%d names will be a stream */

    factory = gst_rtsp_media_factory_new ();

    snprintf(buf, sizeof(buf),
             "( udpsrc port=5600 ! application/x-rtp,media=video,clock-rate=90000,encoding-name=H%d ! rtph%ddepay ! rtph%dpay name=pay0 pt=96 config-interval=1 aggregate-mode=zero-latency mtu=%d )",
             mode, mode, mode, mtu);

    gst_rtsp_media_factory_set_launch (factory, buf);
    gst_rtsp_media_factory_set_shared (factory, TRUE);

    /* attach the test factory to the /test url */
    gst_rtsp_mount_points_add_factory (mounts, "/wfb", factory);

    /* don't need the ref to the mapper anymore */
    g_object_unref (mounts);

    /* attach the server to the default maincontext */
    if (gst_rtsp_server_attach (server, NULL) == 0)
        goto failed;

    /* add a timeout for the session cleanup */
    g_timeout_add_seconds (2, (GSourceFunc) timeout, server);

    /* start serving, this never stops */
    g_print ("H%d stream with mtu %d ready at rtsp://127.0.0.1:8554/wfb\n", mode, mtu);
    g_main_loop_run (loop);

    return 0;

    /* ERRORS */
failed:
    {
        g_print ("failed to attach the server\n");
        return -1;
    }
}
