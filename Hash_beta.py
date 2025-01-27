

import md5
import sha512

import tkinter as tk



class hash:
 def __init__(self):
 
  self.algo
  self.data_input

 
 def algo_f():
  algo = algo.get().tk.StringVar()
   
 
 def data_input_f():
  data_input = data_input.get().tk.StringVar()
 
 def hashText(message,algo):
    
    if algo=="md5" and message:
         return (md5.md5sum(bytes(message,"utf-8")))
    
    
    elif algo=="sha512" and message:
         return ((sha512.sha512(message)))
    
    else:
        return ("error")
    
    
    




    

    





