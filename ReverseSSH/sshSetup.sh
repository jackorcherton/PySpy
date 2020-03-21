#!/bin/bash
#Script creates automatic reverse SSH connection to server
#Stored on BBB, in home directory

#Create a connection to Azure Server (authenticates through RSA key share)
ssh -N -R 2222:localhost:22 Jordan@51.143.178.149
if [[ $? -eq 0 ]]; then
    echo SSH setup Successfull
else
    #If unsuccessful - the error is logged in a log file (tunnel.log)
    echo Error Setting up SSH. RC was $?
fi