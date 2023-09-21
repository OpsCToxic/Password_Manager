import tkinter as tk
from tkinter import NS, Canvas, Scrollbar, ttk

def create_tv_layout(container):
     # container is our root window
    canvas = tk.Canvas(container)
    yscrollbar = ttk.Scrollbar(canvas, orient='vertical')
    tree = ttk.Treeview(canvas, yscrollcommand=yscrollbar.set, columns=("c0","c1","c2"))
    tree.grid(row=0,column=0,rowspan=10,columnspan=3)

    tree.column("#0", width=50, anchor=tk.W, stretch=tk.NO)
    tree.column("#1", anchor=tk.W, stretch=tk.NO)
    tree.column("#2", anchor=tk.W, stretch=tk.NO)

    tree.heading("#0", text="ID")
    tree.heading("#1", text="First Name")
    tree.heading("#2", text="Last Name")

    tree.insert('', 'end', text="1", values=('Adam', 'Smith'))
    tree.insert('', 'end', text="2", values=('Adam', 'Smith'))
    tree.insert('', 'end', text="1", values=('Adam', 'Smith'))
    tree.insert('', 'end', text="1", values=('Adam', 'Smith'))
    tree.insert('', 'end', text="1", values=('Adam', 'Smith'))
    tree.insert('', 'end', text="1", values=('Adam', 'Smith'))
    tree.insert('', 'end', text="1", values=('Adam', 'Smith'))
    tree.insert('', 'end', text="1", values=('Adam', 'Smith'))
    tree.insert('', 'end', text="1", values=('Adam', 'Smith'))
    tree.insert('', 'end', text="1", values=('Adam', 'Smith'))
    tree.insert('', 'end', text="100", values=('Adam', 'Smith'))
    tree.insert('', 'end', text="1", values=('Adam', 'Smith'))

    yscrollbar.configure(command=tree.yview)
    yscrollbar.grid(row=0, column=3, rowspan=10, sticky=NS)
    return canvas

window = tk.Tk()
window.geometry("800x500")
window.title("Scrollbar")

window.configure(bg="LightBlue")

window.resizable(0,0)

tree_view_layout = create_tv_layout(window)
tree_view_layout.grid(column=0, row=0)

window.mainloop()