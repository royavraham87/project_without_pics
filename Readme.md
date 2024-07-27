# This is the library project 

### Creating a virtual env
1. py -m virtualenv env
2. .\env\Scripts\activate

### The program

* currently there is only back and no front. the program is tested with "Tunder Client". the program is for managing books in the library.
there are 2 roles: "Admin" and "Customer", each can do specific functions. regular customers can see all books, loan a book, return a book.
Admins can add/update/toggle customers/books, get the list of loans and the list of late loans, also they can see all the books. they can't loan/return books. 

### Aplications

1. register (admin and customers) - working
2. login (admin and customers) - working
3. logout (admin and customers) - working
4. profile - allow users to add more info about themselves  (admin and customers) - working
5. add_book (admin) - working
6. books- see all the books (works for both admin and customer) - working
7. customers- see all customers (admin)- working
8. toggle_customer/<int:id> (admin)- switches between active and non active customer- working
9. toggle_book/<int:id> (admin)- switches between active and non active book- working
10. update_book/<int:id> (admin) - working
11. find_book - search for a book by name (admin and customer) - working
12. find_customer - search for a customer my name (admin) - working
13. loan_book - allows a customer to loan a book from the library (customer) - working
14. return_book - allows a customer to return the book to the library (customer) - working
15. loans - allows the admin to get the current active loans or the customer active loans (admin and customer) - working
16. loan_his - allows the admin to see the loan history or the customer loan history (admin and customer) - working
17. late_loans - allows the admin to see all the books that return to the library after their return time has past (admin) - working


uploading to a new repository in github
echo "# library_proj_jwt_2024_V2" >> README.md
git init
git add README.md
git commit -m "first commit"
git branch -M main
git remote add origin https://github.com/royavraham87/library_proj_jwt_2024_V2.git
git push -u origin main


push to existing repository in githab
git remote add origin https://github.com/royavraham87/library_proj_jwt_2024_V2.git
git branch -M main
git push -u origin main