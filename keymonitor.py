import pyHook, pythoncom, sys, logging, datetime, base64, win32con, win32api, os
from Tkinter import*
from Crypto.Cipher import AES

total_events = 0

list = []

file = 'output.txt'

key = "1509782315097823"

def OnKeyboardEvent(event):
	#declare gobal variable
	global total_events
	#open file or create file in append mode
	with open(file,'a') as log_file:
		#set variable to contain keyID
		keyStroke = chr(event.KeyID)
		#assign current time to variable parse string
		now = str(datetime.datetime.now())
		#assign window name containing key press to variable
		application = event.WindowName
		#increment counter by one
		total_events +=1
		#variable equals keyID, Timestamp, WindowName and event counter 
		data = (keyStroke + ' ['+ now +'] ['+ application +'] Event Counter ['+ str(total_events) +']' + '\n')
		#create new AES cipher using key
		enc = AES.new(key[:32])
		#apply algorithm and padding to byte block
		AES_string = (str(data) + (AES.block_size - len(str(data)) % AES.block_size) * "\0")
		#encrypt key and apply bas64 to string
		cipher = base64.b64encode(enc.encrypt(AES_string))
		#write cipher text to file and new line
		log_file.write(cipher + '\n')
		#close file
		log_file.close()
		return True

def decryptLog(popEntry,popWindow):
	#get input from entry field
	enteredkey = popEntry.get()
	#if input matches key
	if enteredkey == key:
		popWindow.destroy()
		#open file in read mode
		with open(file,'r') as log_file:
			#unhide file
			win32api.SetFileAttributes(file, win32con.FILE_ATTRIBUTE_NORMAL)
			#for each line in the ouput.txt file
			for line in log_file:
				#create new AES cipher using key
				dec = AES.new(key[:32])
				#decrypt line of cipher text
				raw_dec = dec.decrypt(base64.b64decode(line))
				#strip padding
				clear = raw_dec.rstrip("\0")
				#add the decrypted line to list
				list.append(clear)
			#close file
			log_file.close()
			
		#open file in write mode
		with open(file,'w') as log_file:
				#for each element in the list
				for elem in list:
					#write element to file
					log_file.write(elem)
				#close file
				log_file.close()
				sys.exit()
	else:
		#if wrong key inputted call error function
		errorWindow()
		
def errorWindow():
	#set window dimensions
	errWindow = Toplevel(window)
	errWindow.geometry('10x60')
	#set labels
	errLabel = Label(errWindow, text="Error")
	errLabel.grid(row=0)
	errLabel.config(font=("Courier",11))
	#set button, call function on click
	errButton = Button(errWindow, text='OK',command=lambda: closeErr(errWindow))
	errButton.grid(row=1,padx=19)
	errButton.config(height=1,width=10)
	
def closeErr(errWindow):
	#close error window
	errWindow.destroy()

def keyWindow():
	#set window dimensions
	popWindow = Toplevel(window)
	popWindow.geometry('300x55')
	#set labels
	popLabel = Label(popWindow, text="Enter key: ")
	popLabel.grid(row=0,column=0)
	popLabel.config(font=("Courier",14))
	#set Entries
	popEntry = Entry(popWindow, width=25)
	popEntry.grid(row=0,column=1)
	#set button, call function on click
	popButton = Button(popWindow, text='Enter',command=lambda: decryptLog(popEntry,popWindow)) 
	popButton.grid(row=1,column=0, columnspan=2, padx=5)
	popButton.config(height=1,width=40)
	
def idWindow():
	#set window dimensions
	idWindow = Toplevel(window)
	idWindow.geometry('300x55')
	#set labels
	idLabel = Label(idWindow, text="Student ID: ")
	idLabel.grid(row=0,column=0)
	idLabel.config(font=("Courier",12))
	#set Entries
	idEntry = Entry(idWindow, width=25)
	idEntry.grid(row=0,column=1)
	#set button, call function on click
	idButton = Button(idWindow, text='Enter',command=lambda: writeID(idEntry,idWindow)) 
	idButton.grid(row=1,column=0, columnspan=2, padx=5)
	idButton.config(height=1,width=40)
	
def writeID(idEntry,idWindow):
	#get entered stuID from entry field
	stuID = idEntry.get()
	#destroy window
	idWindow.destroy()
	stuString = ('Student ID: ' + stuID + '\n')
	#open file or create file in append mode
	with open(file,'a') as log_file:
		#set file to hidden
		win32api.SetFileAttributes(file,win32con.FILE_ATTRIBUTE_HIDDEN)
		#create new AES cipher using key
		enc = AES.new(key[:32])
		#apply algorithm and padding to byte block
		AES_string = (str(stuString) + (AES.block_size - len(str(stuString)) % AES.block_size) * "\0")
		#encrypt key and apply bas64 to string
		cipher = base64.b64encode(enc.encrypt(AES_string))
		#write cipher text to file and new line
		log_file.write(cipher + '\n')
		#close file
		log_file.close()
	#call hook function
	setup_hook()
	
def exit():
	#exit program 
    sys.exit()

def setup_hook():
	#minimise window
    window.withdraw()
    hooks_manager = pyHook.HookManager()
	#on key press call function
    hooks_manager.KeyDown = OnKeyboardEvent
	#hook keyboard
    hooks_manager.HookKeyboard()
	#pump all messages from thread
    pythoncom.PumpMessages()
	
#declare window, title and dimensions
window = Tk()
window.title('Monitor')
window.geometry("468x210")
#convert value to int
checkVal = IntVar()

def check():
	#if check box equals not checked
    if checkVal.get() == 0:
		#disable start button
        start_button.configure(state='disabled')
    else:
		#enable start button
        start_button.configure(state='normal')

#set listbox
list1=Listbox(window,height=10,width=75)
list1.grid(row=0,column=0,columnspan=4,rowspan=7,pady=7,padx=7)
list1.insert(1, "                                                        Terms and Conditions")
list1.insert(2, " All key strokes will be logged from the initiaion to the termination of the program.")
list1.insert(3, " The data collected will only be used for the detection and analysis of plagiarism.")
list1.insert(4, " The data will be strictly confidential and only viewed by the unit examiner.")
list1.insert(5, " The monitor will only be active with the USB inserted and the Start button is pressed.")
list1.insert(6, "                                                              Honour Code")
list1.insert(7, " I declare that this piece of work is original and my own words.")
list1.insert(8, " I pledge that I will not take part in any unethical conduct.")
list1.insert(9, " I acknowledge the consequences of plagiarism and that it may lead to exclusion.")
list1.insert(10, " I understand the importance of maintaining the integrity within academia.")
#set checkbox, call function
yes_check=Checkbutton(window,text="Agree to Terms and Conditions", variable=checkVal, command=check)
yes_check.grid(row =10, column =0, padx=5,sticky='w')
#set button
start_button=Button(window,text="Start", state='disabled',command=idWindow)
start_button.config(height=1,width=10)
start_button.grid(row =10, column=1,padx=0,sticky='w')
#set button
exit_button=Button(window,text="Exit", command=exit)
exit_button.config(height=1,width=10)
exit_button.grid(row =10, column=2,padx=0,sticky='w')
#set button
decrypt_button=Button(window,text="Result", command=keyWindow)
decrypt_button.config(height=1,width=10)
decrypt_button.grid(row =10, column=3,padx=0,sticky='w')

#call window
window.mainloop()
