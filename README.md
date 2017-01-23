This is a completely rewrited from scratch version of https://befinitiv.wordpress.com/wifibroadcast-analog-like-transmission-of-live-video-data/
The main modification is how to data are encapsulated into ieee80211 frames. The original wifibroadcast/wifibroadcast-ez accepts stream
of bytes and split them into packets don't related to x264 stream structure. This can emit up to 100ms latencies.  In my case wifibroadcast accepts
UDP stream (for example x264 encapsulated into RTP packets). This provides low latency streaming.

Sample usage chain:
```
Camera -> gstreamer --[RTP stream (UDP)]--> wifibroadcast_tx --//--[ RADIO ]\
  --//--> wifibroadcast_rx --[RTP stream (UDP)]--> gstreamer --> Display
```

For encode logitech c920 camera:
```
gst-launch-1.0 uvch264src device=/dev/video0 initial-bitrate=6000000 average-bitrate=6000000 iframe-period=1000 name=src auto-start=true \
               src.vidsrc ! queue ! video/x-h264,width=1920,height=1080,framerate=30/1 ! h264parse ! rtph264pay ! udpsink host=localhost port=5600
```

To decode:
```
 gst-launch-1.0 udpsrc port=5600 caps='application/x-rtp, media=(string)video, clock-rate=(int)90000, encoding-name=(string)H264' \
               ! rtph264depay ! avdec_h264 ! clockoverlay valignment=bottom ! autovideosink fps-update-interval=1000 sync=false
```


Supported WiFi hardware:  Ralink RT2800. Was tested with ALPHA AWUS05NH v2 in 5GHz mode. To disable ieee80211 autospeed and maximize output power you
need to apply kernel patches from ``patches`` directory. See https://github.com/bortek/EZ-WifiBroadcast/wiki for details.