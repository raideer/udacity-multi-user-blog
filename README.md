# [3. Udacity Project](https://udacity-multi-user-blog-172423.appspot.com/)
Udacity Full stack Web developer nanodegree
### Build a Multi user blog
_[Preview](https://udacity-multi-user-blog-172423.appspot.com/)_

### Features
- User registration/authorization with cookies
- Basic security measures like cookie validation and password salting + hashing
- Ability to create, edit and delete own posts
- Ability to create, edit and delete comments
- Ability to upvote/downvote posts (without refreshing the page - via ajax)
- Profile page that shows all posts and comments made by authorized user

### Frontend libraries
- jQuery
- Bootstrap (With the bootswatch readable theme)

### Running the code
[Google Cloud SDK with the Python extra components is required!](https://cloud.google.com/appengine/docs/standard/python/download)

#### Locally
1. Clone the repo `git clone https://github.com/raideer/udacity-project-3`
2. `cd udacity-project-3`
3. Run `dev_appserver.py .`
4. The page now should be running on `localhost:8080`

#### On Google cloud
1. Clone the repo `git clone https://github.com/raideer/udacity-project-3`
2. `cd udacity-project-3`
3. Initialize gcloud with `gcloud init`
4. Deploy the app with `gcloud app deploy`
5. - [You might need to wait couple minutes while google is indexing the database](https://console.cloud.google.com/datastore/indexes)
    - If there aren't [any indexes showing up](https://console.cloud.google.com/datastore/indexes), you might need to redeploy the index.yaml file with `gcloud deploy index.yaml`
    
6. Open the page with `gcloud app browse`
