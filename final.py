import os
import tkinter as tk
from tkinter import ttk, filedialog, messagebox, scrolledtext
import threading
import datetime
from asd import SecureFileSystem, logger
import logging

class SecureFileSystemGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("Secure File System")
        self.root.geometry("900x700")
        self.root.minsize(900, 700)
        
        # Initialize the secure file system
        self.secure_fs = SecureFileSystem()
        
        # Password for encryption/decryption
        self.current_password = "default_password"
        
        # Set up the GUI components
        self.setup_gui()
        
        # Load initial files
        self.refresh_file_list()
        
        # Set up logging to text widget
        self.setup_logging()
    
    def setup_logging(self):
        # Create a handler that logs to the text widget
        class TextHandler(logging.Handler):
            def __init__(self, text_widget):
                logging.Handler.__init__(self)
                self.text_widget = text_widget
            
            def emit(self, record):
                msg = self.format(record)
                def append():
                    self.text_widget.configure(state='normal')
                    self.text_widget.insert(tk.END, msg + '\n')
                    self.text_widget.configure(state='disabled')
                    self.text_widget.see(tk.END)
                self.text_widget.after(0, append)
        
        # Create text handler and add it to logger
        text_handler = TextHandler(self.log_text)
        text_handler.setFormatter(logging.Formatter('%(asctime)s - %(levelname)s - %(message)s'))
        logger.addHandler(text_handler)

    def setup_gui(self):
        # Create a main frame
        main_frame = ttk.Frame(self.root, padding="10")
        main_frame.pack(fill=tk.BOTH, expand=True)
        
        # Create paned window to separate file list and log area
        paned_window = ttk.PanedWindow(main_frame, orient=tk.VERTICAL)
        paned_window.pack(fill=tk.BOTH, expand=True, pady=5)
        
        # Top frame for upload controls
        top_frame = ttk.Frame(main_frame)
        top_frame.pack(fill=tk.X, pady=5)
        
        # Middle frame for file list
        middle_frame = ttk.LabelFrame(paned_window, text="Files")
        paned_window.add(middle_frame, weight=3)
        
        # Bottom frame for logs
        bottom_frame = ttk.LabelFrame(paned_window, text="Logs")
        paned_window.add(bottom_frame, weight=1)
        
        # Upload section
        ttk.Label(top_frame, text="Password:").pack(side=tk.LEFT, padx=5)
        self.password_var = tk.StringVar(value=self.current_password)
        password_entry = ttk.Entry(top_frame, textvariable=self.password_var, show="*", width=20)
        password_entry.pack(side=tk.LEFT, padx=5)
        
        show_password_var = tk.BooleanVar()
        show_password_check = ttk.Checkbutton(
            top_frame, text="Show", variable=show_password_var,
            command=lambda: password_entry.config(show="" if show_password_var.get() else "*")
        )
        show_password_check.pack(side=tk.LEFT, padx=5)
        
        ttk.Button(top_frame, text="Upload File", command=self.upload_file).pack(side=tk.LEFT, padx=20)
        ttk.Button(top_frame, text="Refresh", command=self.refresh_file_list).pack(side=tk.LEFT, padx=5)
        
        # File list section
        file_frame = ttk.Frame(middle_frame)
        file_frame.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        # Create Treeview with scrollbars
        columns = ("secure_id", "original_name", "upload_time", "file_type", "size")
        self.file_tree = ttk.Treeview(file_frame, columns=columns, show="headings", selectmode="browse")
        
        # Define column headings
        self.file_tree.heading("secure_id", text="Secure ID")
        self.file_tree.heading("original_name", text="Original Name")
        self.file_tree.heading("upload_time", text="Upload Time")
        self.file_tree.heading("file_type", text="File Type")
        self.file_tree.heading("size", text="Size")
        
        # Define column widths
        self.file_tree.column("secure_id", width=150)
        self.file_tree.column("original_name", width=200)
        self.file_tree.column("upload_time", width=150)
        self.file_tree.column("file_type", width=150)
        self.file_tree.column("size", width=100)
        
        # Add scrollbars
        tree_scroll_y = ttk.Scrollbar(file_frame, orient=tk.VERTICAL, command=self.file_tree.yview)
        tree_scroll_x = ttk.Scrollbar(file_frame, orient=tk.HORIZONTAL, command=self.file_tree.xview)
        self.file_tree.configure(yscrollcommand=tree_scroll_y.set, xscrollcommand=tree_scroll_x.set)
        
        # Pack the treeview and scrollbars
        tree_scroll_y.pack(side=tk.RIGHT, fill=tk.Y)
        tree_scroll_x.pack(side=tk.BOTTOM, fill=tk.X)
        self.file_tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        
        # Action buttons
        button_frame = ttk.Frame(middle_frame)
        button_frame.pack(fill=tk.X, padx=5, pady=5)
        
        ttk.Button(button_frame, text="Download", command=self.download_file).pack(side=tk.LEFT, padx=5)
        ttk.Button(button_frame, text="Delete", command=self.delete_file).pack(side=tk.LEFT, padx=5)
        ttk.Button(button_frame, text="View Details", command=self.view_file_details).pack(side=tk.LEFT, padx=5)
        
        # Log area
        log_frame = ttk.Frame(bottom_frame)
        log_frame.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        self.log_text = scrolledtext.ScrolledText(log_frame, wrap=tk.WORD, state='disabled')
        self.log_text.pack(fill=tk.BOTH, expand=True)
        
        # Status bar
        self.status_var = tk.StringVar()
        status_bar = ttk.Label(main_frame, textvariable=self.status_var, anchor=tk.W, relief=tk.SUNKEN)
        status_bar.pack(fill=tk.X, side=tk.BOTTOM, pady=2)
        
        # Bind context menu to right-click
        self.create_context_menu()
        
        # Set status
        self.set_status("Ready")
    
    def create_context_menu(self):
        self.context_menu = tk.Menu(self.root, tearoff=0)
        self.context_menu.add_command(label="Download", command=self.download_file)
        self.context_menu.add_command(label="Delete", command=self.delete_file)
        self.context_menu.add_command(label="View Details", command=self.view_file_details)
        
        self.file_tree.bind("<Button-3>", self.show_context_menu)
    
    def show_context_menu(self, event):
        # Select the item the user right-clicked on
        item = self.file_tree.identify_row(event.y)
        if item:
            self.file_tree.selection_set(item)
            self.context_menu.post(event.x_root, event.y_root)
    
    def upload_file(self):
        # Get selected files
        file_paths = filedialog.askopenfilenames(
            title="Select file(s) to upload",
            filetypes=[("All Files", "*.*")]
        )
        
        if not file_paths:
            return
        
        # Get password
        self.current_password = self.password_var.get()
        
        # Start upload in a separate thread to keep GUI responsive
        threading.Thread(target=self._upload_files, args=(file_paths,), daemon=True).start()
    
    def _upload_files(self, file_paths):
        self.set_status("Uploading files...")
        
        for file_path in file_paths:
            try:
                # Update GUI to show we're processing this file
                file_name = os.path.basename(file_path)
                self.set_status(f"Processing {file_name}...")
                
                # Process the file
                result = self.secure_fs.process_file(file_path, password=self.current_password)
                
                # Log the encryption key (password)
                logger.info(f"File '{file_name}' encrypted with key: {self.current_password}")
                
                # Update GUI in the main thread
                self.root.after(0, lambda r=result: self._handle_upload_result(r))
                
            except Exception as e:
                logger.error(f"Error uploading file {file_path}: {str(e)}")
                self.set_status(f"Error uploading {file_name}")
        
        # Refresh the file list
        self.root.after(0, self.refresh_file_list)
        self.set_status("Upload complete")
    
    def _handle_upload_result(self, result):
        if result["status"] == "success":
            messagebox.showinfo("Upload Successful", 
                               f"File '{result['file_name']}' uploaded successfully.\n"
                               f"Secure ID: {result['secure_id']}")
        else:
            messagebox.showerror("Upload Failed", result["message"])
    
    def refresh_file_list(self):
        # Clear the current items
        for item in self.file_tree.get_children():
            self.file_tree.delete(item)
        
        # Get and display files
        files = self.secure_fs.list_files()
        
        for file in files:
            self.file_tree.insert("", tk.END, values=(
                file["secure_id"],
                file["original_name"],
                file["upload_time"],
                file["file_type"],
                self.format_size(file["size"])
            ))
        
        self.set_status(f"Showing {len(files)} files")
    
    def download_file(self):
        # Get selected item
        selected_items = self.file_tree.selection()
        if not selected_items:
            messagebox.showwarning("No Selection", "Please select a file to download")
            return
        
        # Get secure ID from the selected item
        item_values = self.file_tree.item(selected_items[0], "values")
        secure_id = item_values[0]
        original_name = item_values[1]
        
        # Get save location
        save_path = filedialog.asksaveasfilename(
            title="Save file as",
            initialfile=original_name,
            defaultextension=".*"
        )
        
        if not save_path:
            return
        
        # Start download in separate thread
        threading.Thread(
            target=self._download_file, 
            args=(secure_id, save_path), 
            daemon=True
        ).start()
    
    def _download_file(self, secure_id, save_path):
        self.set_status(f"Downloading file {secure_id}...")
        
        try:
            # Get password
            password = self.password_var.get()
            
            # Retrieve and decrypt the file
            file_data, original_name = self.secure_fs.retrieve_file(secure_id, password)
            
            if file_data is None:
                self.root.after(0, lambda: messagebox.showerror(
                    "Download Failed", 
                    "Could not retrieve or decrypt the file. Check the password."
                ))
                self.set_status("Download failed")
                return
            
            # Write the file
            with open(save_path, 'wb') as f:
                f.write(file_data)
            
            # Show success message
            self.root.after(0, lambda: messagebox.showinfo(
                "Download Complete", 
                f"File saved to {save_path}"
            ))
            
            # Log the decryption key used
            logger.info(f"File '{original_name}' (ID: {secure_id}) decrypted with key: {password}")
            
        except Exception as e:
            logger.error(f"Error downloading file {secure_id}: {str(e)}")
            self.root.after(0, lambda: messagebox.showerror(
                "Download Error", 
                f"An error occurred: {str(e)}"
            ))
        
        self.set_status("Ready")
    
    def delete_file(self):
        # Get selected item
        selected_items = self.file_tree.selection()
        if not selected_items:
            messagebox.showwarning("No Selection", "Please select a file to delete")
            return
        
        # Get secure ID from the selected item
        item_values = self.file_tree.item(selected_items[0], "values")
        secure_id = item_values[0]
        file_name = item_values[1]
        
        # Confirm deletion
        if not messagebox.askyesno("Confirm Delete", f"Are you sure you want to delete '{file_name}'?"):
            return
        
        # Delete the file
        if self.secure_fs.delete_file(secure_id):
            messagebox.showinfo("Success", "File deleted successfully")
            # Refresh the file list
            self.refresh_file_list()
        else:
            messagebox.showerror("Error", "Could not delete the file")
    
    def view_file_details(self):
        # Get selected item
        selected_items = self.file_tree.selection()
        if not selected_items:
            messagebox.showwarning("No Selection", "Please select a file to view details")
            return
        
        # Get values from the selected item
        values = self.file_tree.item(selected_items[0], "values")
        
        # Create details window
        details_window = tk.Toplevel(self.root)
        details_window.title("File Details")
        details_window.geometry("500x300")
        details_window.minsize(500, 300)
        details_window.transient(self.root)
        details_window.grab_set()
        
        # Add file details
        frame = ttk.Frame(details_window, padding="10")
        frame.pack(fill=tk.BOTH, expand=True)
        
        # Create labels and fields
        ttk.Label(frame, text="Secure ID:", font=("", 10, "bold")).grid(row=0, column=0, sticky=tk.W, pady=5)
        ttk.Label(frame, text=values[0], wraplength=400).grid(row=0, column=1, sticky=tk.W, pady=5)
        
        ttk.Label(frame, text="Original Name:", font=("", 10, "bold")).grid(row=1, column=0, sticky=tk.W, pady=5)
        ttk.Label(frame, text=values[1], wraplength=400).grid(row=1, column=1, sticky=tk.W, pady=5)
        
        ttk.Label(frame, text="Upload Time:", font=("", 10, "bold")).grid(row=2, column=0, sticky=tk.W, pady=5)
        ttk.Label(frame, text=values[2], wraplength=400).grid(row=2, column=1, sticky=tk.W, pady=5)
        
        ttk.Label(frame, text="File Type:", font=("", 10, "bold")).grid(row=3, column=0, sticky=tk.W, pady=5)
        ttk.Label(frame, text=values[3], wraplength=400).grid(row=3, column=1, sticky=tk.W, pady=5)
        
        ttk.Label(frame, text="Size:", font=("", 10, "bold")).grid(row=4, column=0, sticky=tk.W, pady=5)
        ttk.Label(frame, text=values[4], wraplength=400).grid(row=4, column=1, sticky=tk.W, pady=5)
        
        ttk.Label(frame, text="Current Encryption Key:", font=("", 10, "bold")).grid(row=5, column=0, sticky=tk.W, pady=5)
        ttk.Label(frame, text=self.password_var.get(), wraplength=400).grid(row=5, column=1, sticky=tk.W, pady=5)
        
        # Add close button
        ttk.Button(frame, text="Close", command=details_window.destroy).grid(row=6, column=0, columnspan=2, pady=20)
    
    def set_status(self, message):
        timestamp = datetime.datetime.now().strftime("%H:%M:%S")
        self.status_var.set(f"{timestamp} - {message}")
    
    @staticmethod
    def format_size(size_bytes):
        """Format file size in a human-readable format"""
        if size_bytes < 1024:
            return f"{size_bytes} B"
        elif size_bytes < 1024 * 1024:
            return f"{size_bytes / 1024:.1f} KB"
        elif size_bytes < 1024 * 1024 * 1024:
            return f"{size_bytes / (1024 * 1024):.1f} MB"
        else:
            return f"{size_bytes / (1024 * 1024 * 1024):.1f} GB"


def main():
    root = tk.Tk()
    app = SecureFileSystemGUI(root)
    root.mainloop()


if __name__ == "__main__":
    main()