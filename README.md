Udacity Blog

The blog can be found at: http://udacity-blog-141420.appspot.com/blog
It can also run locally with Google App Engine: create a new project via the GAE Launcher, move the files in the specific directory, and run it in the launcher.

-------------------------------------------

Using the website:

On the pages that don't involve authentication, users have the possibility to click on the buttons in the upper part in order to sign up, log in or log out(they will be redirected to the '/blog' page afterwards). By clicking on the big title, they will be redirected to the '/blog' page. Also, their username will be displayed in the top-right corner after they log in.

The '/blog' page contains all the posts submitted so far. 
	- To add a new post, click on 'Add post'
	- To open a post's individual page, click on the post's title

On the individual page of the post, users can see a specific post, its comments, and its number of likes. 
	- To edit the post, click on its content (*)
	- To delete the post, click on 'Delete post' (*)
	- To edit a comment, click on its content (*)
	- To delete a comment, click on 'Delete comment' (*)
	- To add a comment, click on 'Add comment'
	- To like/unlike the post, click on 'Like'/'Unlike' (**)

(*) = Can only be done by the owner of the post/comment
(**) = Cannot be done by the owner of the post

The authentication pages, as well as the pages for creating or editing posts or comments are user friendly, and error notifications will pop up if needed.

-------------------------------------------

Unregistred visitors that try to create posts/comments or to like posts will be redirected to the log in page.
Users trying to edit posts/comments that don't belong to them will be prompted an error message. The same goes for trying to like their own posts.

Users will remain logged in during the current session, unless they destroy the cookie.