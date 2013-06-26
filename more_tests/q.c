#define DBUS_API_SUBJECT_TO_CHANGE
#include <dbus/dbus.h>
#include <stdbool.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
 
static void send_dbus_message (DBusConnection *connection, const char *msg)
{
    DBusMessage *message;
    //initiliaze the message
    message = dbus_message_new_signal ("/org/developers/blog/tablet/event",
                                       "org.developers.blog.tablet.text.focus.event",
                                       msg);
    
    //send the message
    dbus_connection_send (connection, message, NULL);
    //deallocate the message
    dbus_message_unref (message);
}
 
int main (int argc, char **argv)
{
    DBusConnection *connection;
    DBusError error;
    
    //init error message
    printf ("init error\n");
    dbus_error_init (&error);
    printf ("done init error\n");
    connection = dbus_bus_get (DBUS_BUS_SESSION, &error);
    printf ("done dbus get\n");
    if (!connection)
    {
        printf ("Connection to D-BUS daemon failed: %s", error.message);
    
        //deallocate error message
        dbus_error_free (&error);
        return 1;
    }
 
    send_dbus_message (connection, "TabletUITextFocusEvent");
    return 0;
}

