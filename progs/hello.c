/* Copyright (c) 2012 the authors listed at the following URL, and/or
the authors of referenced articles or incorporated external code:
http://en.literateprograms.org/Hello_World_(C,_Xlib)?action=history&offset=20081030200625

Permission is hereby granted, free of charge, to any person obtaining
a copy of this software and associated documentation files (the
"Software"), to deal in the Software without restriction, including
without limitation the rights to use, copy, modify, merge, publish,
distribute, sublicense, and/or sell copies of the Software, and to
permit persons to whom the Software is furnished to do so, subject to
the following conditions:

The above copyright notice and this permission notice shall be
included in all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY
CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT,
TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE
SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

Retrieved from: http://en.literateprograms.org/Hello_World_(C,_Xlib)?oldid=15369
*/



#include<X11/Xlib.h>



#include<stdio.h>

#include<stdlib.h>



int main()

{

  Display *dpy;

  Window rootwin;

  Window win;

  Colormap cmap;

  XEvent e;

  int scr;

  GC gc;





  if(!(dpy=XOpenDisplay(NULL))) {

    fprintf(stderr, "ERROR: could not open display\n");

    exit(1);

  }



  scr = DefaultScreen(dpy);

  rootwin = RootWindow(dpy, scr);

  cmap = DefaultColormap(dpy, scr);





  win=XCreateSimpleWindow(dpy, rootwin, 1, 1, 100, 50, 0, 

			  BlackPixel(dpy, scr), BlackPixel(dpy, scr));



  XStoreName(dpy, win, "hello");





  gc=XCreateGC(dpy, win, 0, NULL);

  XSetForeground(dpy, gc, WhitePixel(dpy, scr));



  XSelectInput(dpy, win, ExposureMask|ButtonPressMask);



  XMapWindow(dpy, win);



  while(1) {

    XNextEvent(dpy, &e);

    if(e.type==Expose && e.xexpose.count<1)

      XDrawString(dpy, win, gc, 10, 10, "Hello World!", 12);

    else if(e.type==ButtonPress) break;

  }





  XCloseDisplay(dpy);



  return 0;

}

