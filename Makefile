CC=g++  -std=c++14
#CFLAGS=-Wall -I/usr/local/Cellar/opencv/4.1.0_2/include -O3 -I/usr/local/include
#CFLAGS=-Wall -I/Users/trx//projetunicorn/opencvstatic/opencv-4.1.0/build/include -O3 -I/usr/local/include
CFLAGS+=-Wall -I/usr/local/Cellar/opencv/4.1.0_2/include/opencv4/opencv2 -I/usr/local/Cellar/opencv/4.1.0_2/include/opencv4 -O3 -I/usr/local/include
#CFLAGSLINK= -lgmp -lpthread  /usr/local/opt/opencv@3/lib/libopencv_core.dylib /usr/local/opt/opencv@3/lib/libopencv_videoio.dylib /usr/local/opt/opencv@3/lib/libopencv_highgui.dylib /usr/local/opt/opencv@3/lib/libopencv_imgproc.dylib /usr/local/opt/opencv@3/lib/libopencv_imgcodecs.dylib -L/usr/local/lib/ -lssl -lcrypto
#CFLAGSLINK= -lgmp -lpthread -L/Users/trx/projetunicorn/opencvstatic/opencv-4.1.0/build/lib -lopencv_core -lopencv_videoio -lopencv_highgui -lopencv_imgproc -lopencv_imgcodecs -L/usr/local/lib/ -lssl -lcrypto
#CFLAGSLINK= -lgmp -lpthread  /usr/local/Cellar/opencv/4.1.0_2/lib/libopencv_core.a /usr/local/Cellar/opencv/4.1.0_2/lib/libopencv_videoio.a /usr/local/Cellar/opencv/4.1.0_2/lib/libopencv_highgui.a /usr/local/opt/opencv@3/lib/libopencv_imgproc.a /usr/local/Cellar/opencv/4.1.0_2/lib/libopencv_imgcodecs.a -L/usr/local/lib/ -lssl -lcrypto
#CFLAGSLINK= -lgmp -lpthread -L/usr/local/Cellar/opencv/4.1.0_2/lib -lopencv_core -lopencv_videoio -lopencv_highgui -lopencv_imgproc -lopencv_imgcodecs -lopencv_calib3d -lopencv_features2d -L/usr/local/lib/ -lssl -lcrypto
CFLAGSLINK+= -lgmp -lpthread -L/usr/local/lib/ -lssl -lcrypto
#CFLAGSLINK+= -L/usr/local/Cellar/opencv/4.1.0_2/lib -lopencv_gapi -lopencv_stitching -lopencv_aruco -lopencv_bgsegm -lopencv_bioinspired -lopencv_ccalib -lopencv_dnn_objdetect -lopencv_dpm -lopencv_face -lopencv_freetype -lopencv_fuzzy -lopencv_hfs -lopencv_img_hash -lopencv_line_descriptor -lopencv_quality -lopencv_reg -lopencv_rgbd -lopencv_saliency -lopencv_sfm -lopencv_stereo -lopencv_structured_light -lopencv_phase_unwrapping -lopencv_superres -lopencv_optflow -lopencv_surface_matching -lopencv_tracking -lopencv_datasets -lopencv_text -lopencv_dnn -lopencv_plot -lopencv_videostab -lopencv_video -lopencv_xfeatures2d -lopencv_shape -lopencv_ml -lopencv_ximgproc -lopencv_xobjdetect -lopencv_objdetect -lopencv_calib3d -lopencv_features2d -lopencv_highgui -lopencv_videoio -lopencv_imgcodecs -lopencv_flann -lopencv_xphoto -lopencv_photo -lopencv_imgproc -lopencv_core
CFLAGSLINK +=  -lopencv_core -lopencv_imgcodecs -lopencv_videoio



SOURCES=

all: clean unicorn clean
unicorn: sloth.o main.o timed_commit.o
	$(CC) $(CFLAGS) $(CFLAGSLINK) sloth.o timed_commit.o main.o -o unicorn
main.o: main.cpp
	$(CC) main.cpp $(SOURCES) $(CFLAGS) -c
sloth.o: sloth.cpp sloth.h
	$(CC) sloth.cpp sloth.h $(SOURCES) $(CFLAGS) -c
timed_commit.o: timed_commit.cpp timed_commit.h
	$(CC) timed_commit.cpp timed_commit.h $(SOURCES) $(CFLAGS) -c
clean:
	rm -rf *.o
	rm -rf *.h.gch
	rm -rf *.h.gch
