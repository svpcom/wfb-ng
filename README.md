Wifibroadcast
-------------

This is transmitter and receiver of UDP packets using raw WiFi radio inspired by https://befinitiv.wordpress.com/wifibroadcast-analog-like-transmission-of-live-video-data/ . The main difference is how to data are encapsulated into ieee80211 frames. The original wifibroadcast accepts stream of bytes and split them into packets without attention to x264 stream elements. This can emit up to 100ms latencies.  In my case wifibroadcast accepts UDP stream (for example x264 encapsulated into RTP packets). This provides low latency streaming.


Wifibroadcast puts the wifi cards into monitor mode. This mode allows to send and receive arbitrary packets without association. Additionally, it is also possible to receive erroneous frames (where the checksum does not match). This way a true unidirectional connection is established which mimics the advantageous properties of an analog link. Those are:

 - The transmitter sends its data regardless of any associated receivers. Thus there is no risk of sudden video stall due to the loss of association

 - The receiver receives video as long as it is in range of the transmitter. If it gets slowly out of range the video quality degrades but does not stall. Even if frames are erroneous they will be displayed instead of being rejected.

 - The traditional scheme “single broadcaster – multiple receivers” works out of the box. If bystanders want to watch the video stream with their devices they just have to “switch to the right channel”

 - Wifibroadcast allows you to use several low cost receivers in parallel and combine their data to increase probability of correct data reception. This so-called software diversity allows you to use identical receivers to improve relieability as well as complementary receivers (think of one receiver with an omnidirectional antenna covering 360° and several directional antennas for high distance all working in parallel)

 - Wifibroadcast uses Forward Error Correction to archive a high reliability at low bandwidth requirements. It is able to repair lost or corrupted packets at the receiver.



Sample usage chain:
```
Camera -> gstreamer --[RTP stream (UDP)]--> wifibroadcast_tx --//--[ RADIO ]--//--> wifibroadcast_rx --[RTP stream (UDP)]--> gstreamer --> Display
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


Supported WiFi hardware:  Ralink RT2800. Was tested with ALPHA AWUS051NH v2 in 5GHz mode. To disable ieee80211 autospeed and maximize output power you
need to apply kernel patches from ``patches`` directory. See https://github.com/bortek/EZ-WifiBroadcast/wiki for details.

Wifibroadcast + PX4 HOWTO: https://dev.px4.io/en/qgc/video_streaming_wifi_broadcast.html
