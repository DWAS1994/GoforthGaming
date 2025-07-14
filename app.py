
from flask import Flask, render_template, request, redirect, url_for, session, flash, jsonify
import sqlite3
import hashlib
import os
from datetime import datetime
import secrets

app = Flask(__name__)
app.secret_key = secrets.token_hex(16)

# Database initialization
def init_db():
    conn = sqlite3.connect('marketplace.db')
    c = conn.cursor()
    
    # Users table
    c.execute('''CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE NOT NULL,
        email TEXT UNIQUE NOT NULL,
        password_hash TEXT NOT NULL,
        is_seller BOOLEAN DEFAULT FALSE,
        seller_fee_paid BOOLEAN DEFAULT FALSE,
        posting_fee_paid BOOLEAN DEFAULT FALSE,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        rating_sum INTEGER DEFAULT 0,
        rating_count INTEGER DEFAULT 0
    )''')
    
    # Add posting_fee_paid column if it doesn't exist (for existing databases)
    try:
        c.execute('ALTER TABLE users ADD COLUMN posting_fee_paid BOOLEAN DEFAULT FALSE')
    except sqlite3.OperationalError:
        # Column already exists
        pass
    
    # Items table
    c.execute('''CREATE TABLE IF NOT EXISTS items (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        title TEXT NOT NULL,
        description TEXT,
        price REAL NOT NULL,
        seller_id INTEGER,
        sold BOOLEAN DEFAULT FALSE,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (seller_id) REFERENCES users (id)
    )''')
    
    # Ratings table
    c.execute('''CREATE TABLE IF NOT EXISTS ratings (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        rater_id INTEGER,
        rated_user_id INTEGER,
        rating INTEGER CHECK(rating >= 1 AND rating <= 5),
        comment TEXT,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (rater_id) REFERENCES users (id),
        FOREIGN KEY (rated_user_id) REFERENCES users (id)
    )''')
    
    # Forum posts table
    c.execute('''CREATE TABLE IF NOT EXISTS forum_posts (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        title TEXT NOT NULL,
        content TEXT NOT NULL,
        category TEXT NOT NULL DEFAULT 'general',
        author_id INTEGER,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (author_id) REFERENCES users (id)
    )''')
    
    # Add category column if it doesn't exist (for existing databases)
    try:
        c.execute('ALTER TABLE forum_posts ADD COLUMN category TEXT DEFAULT "general"')
    except sqlite3.OperationalError:
        # Column already exists
        pass
    
    # Forum replies table
    c.execute('''CREATE TABLE IF NOT EXISTS forum_replies (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        post_id INTEGER,
        content TEXT NOT NULL,
        author_id INTEGER,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (post_id) REFERENCES forum_posts (id),
        FOREIGN KEY (author_id) REFERENCES users (id)
    )''')
    
    conn.commit()
    conn.close()

def hash_password(password):
    return hashlib.sha256(password.encode()).hexdigest()

def get_db_connection():
    conn = sqlite3.connect('marketplace.db')
    conn.row_factory = sqlite3.Row
    return conn

@app.route('/')
def home():
    conn = get_db_connection()
    items = conn.execute('''
        SELECT i.*, u.username as seller_name 
        FROM items i 
        JOIN users u ON i.seller_id = u.id 
        WHERE i.sold = FALSE 
        ORDER BY i.created_at DESC
    ''').fetchall()
    conn.close()
    return render_template('home.html', items=items)

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        email = request.form['email']
        password = request.form['password']
        
        if not username or not email or not password:
            flash('All fields are required')
            return render_template('register.html')
        
        conn = get_db_connection()
        try:
            conn.execute('''
                INSERT INTO users (username, email, password_hash)
                VALUES (?, ?, ?)
            ''', (username, email, hash_password(password)))
            conn.commit()
            flash('Registration successful! Please login.')
            return redirect(url_for('login'))
        except sqlite3.IntegrityError:
            flash('Username or email already exists')
        finally:
            conn.close()
    
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        conn = get_db_connection()
        user = conn.execute('''
            SELECT * FROM users WHERE username = ? AND password_hash = ?
        ''', (username, hash_password(password))).fetchone()
        conn.close()
        
        if user:
            session['user_id'] = user['id']
            session['username'] = user['username']
            session['is_seller'] = user['is_seller']
            return redirect(url_for('home'))
        else:
            flash('Invalid credentials')
    
    return render_template('login.html')

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('home'))

@app.route('/become_seller', methods=['GET', 'POST'])
def become_seller():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    if request.method == 'POST':
        transaction_id = request.form.get('transaction_id', '').strip()
        
        if transaction_id:
            # In a real application, you would verify the transaction on the blockchain
            # For now, we'll accept any non-empty transaction ID as valid
            conn = get_db_connection()
            conn.execute('''
                UPDATE users SET is_seller = TRUE, seller_fee_paid = TRUE 
                WHERE id = ?
            ''', (session['user_id'],))
            conn.commit()
            conn.close()
            
            session['is_seller'] = True
            flash(f'Payment confirmed! Transaction ID: {transaction_id}. You are now a seller.')
            return redirect(url_for('sell_item'))
        else:
            flash('Please provide a valid transaction ID.')
    
    return render_template('become_seller.html')

@app.route('/sell', methods=['GET', 'POST'])
def sell_item():
    if 'user_id' not in session or not session.get('is_seller'):
        flash('You must be a registered seller to list items.')
        return redirect(url_for('become_seller'))
    
    # Check if posting fee is paid
    conn = get_db_connection()
    user = conn.execute('SELECT posting_fee_paid FROM users WHERE id = ?', (session['user_id'],)).fetchone()
    conn.close()
    
    if not user['posting_fee_paid']:
        flash('You must pay the posting fee before listing items.')
        return redirect(url_for('pay_posting_fee'))
    
    if request.method == 'POST':
        title = request.form['title']
        description = request.form['description']
        price = float(request.form['price'])
        
        conn = get_db_connection()
        conn.execute('''
            INSERT INTO items (title, description, price, seller_id)
            VALUES (?, ?, ?, ?)
        ''', (title, description, price, session['user_id']))
        conn.commit()
        conn.close()
        
        flash('Item listed successfully!')
        return redirect(url_for('home'))
    
    return render_template('sell_item.html')

@app.route('/buy/<int:item_id>')
def buy_item(item_id):
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    conn = get_db_connection()
    conn.execute('UPDATE items SET sold = TRUE WHERE id = ?', (item_id,))
    conn.commit()
    conn.close()
    
    flash('Item purchased successfully!')
    return redirect(url_for('home'))

@app.route('/rate_user/<int:user_id>', methods=['GET', 'POST'])
def rate_user(user_id):
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    if request.method == 'POST':
        rating = int(request.form['rating'])
        comment = request.form['comment']
        
        conn = get_db_connection()
        # Check if user already rated this person
        existing = conn.execute('''
            SELECT id FROM ratings WHERE rater_id = ? AND rated_user_id = ?
        ''', (session['user_id'], user_id)).fetchone()
        
        if not existing:
            conn.execute('''
                INSERT INTO ratings (rater_id, rated_user_id, rating, comment)
                VALUES (?, ?, ?, ?)
            ''', (session['user_id'], user_id, rating, comment))
            
            # Update user's rating summary
            conn.execute('''
                UPDATE users SET 
                    rating_sum = rating_sum + ?,
                    rating_count = rating_count + 1
                WHERE id = ?
            ''', (rating, user_id))
            
            conn.commit()
            flash('Rating submitted successfully!')
        else:
            flash('You have already rated this user.')
        
        conn.close()
        return redirect(url_for('user_profile', user_id=user_id))
    
    conn = get_db_connection()
    user = conn.execute('SELECT username FROM users WHERE id = ?', (user_id,)).fetchone()
    conn.close()
    
    return render_template('rate_user.html', user=user, user_id=user_id)

@app.route('/user/<int:user_id>')
def user_profile(user_id):
    conn = get_db_connection()
    user = conn.execute('SELECT * FROM users WHERE id = ?', (user_id,)).fetchone()
    ratings = conn.execute('''
        SELECT r.*, u.username as rater_name 
        FROM ratings r 
        JOIN users u ON r.rater_id = u.id 
        WHERE r.rated_user_id = ?
        ORDER BY r.created_at DESC
    ''', (user_id,)).fetchall()
    conn.close()
    
    avg_rating = user['rating_sum'] / user['rating_count'] if user['rating_count'] > 0 else 0
    
    return render_template('user_profile.html', user=user, ratings=ratings, avg_rating=avg_rating)

@app.route('/forum')
@app.route('/forum/<category>')
def forum(category=None):
    if 'user_id' not in session:
        flash('You must be logged in to access the forum.')
        return redirect(url_for('login'))
    
    conn = get_db_connection()
    
    if category:
        posts = conn.execute('''
            SELECT p.*, u.username as author_name,
                   COUNT(r.id) as reply_count
            FROM forum_posts p 
            JOIN users u ON p.author_id = u.id 
            LEFT JOIN forum_replies r ON p.id = r.post_id
            WHERE p.category = ?
            GROUP BY p.id
            ORDER BY p.created_at DESC
        ''', (category,)).fetchall()
    else:
        posts = conn.execute('''
            SELECT p.*, u.username as author_name,
                   COUNT(r.id) as reply_count
            FROM forum_posts p 
            JOIN users u ON p.author_id = u.id 
            LEFT JOIN forum_replies r ON p.id = r.post_id
            GROUP BY p.id
            ORDER BY p.created_at DESC
        ''').fetchall()
    
    conn.close()
    
    categories = [
        ('game_items', 'Game Items & Equipment'),
        ('accounts', 'Game Accounts'),
        ('currency', 'Game Currency'),
        ('chat', 'Gaming Chat'),
        ('general', 'General Discussion')
    ]
    
    return render_template('forum.html', posts=posts, categories=categories, current_category=category)

@app.route('/forum/post/<int:post_id>')
def forum_post(post_id):
    if 'user_id' not in session:
        flash('You must be logged in to view forum posts.')
        return redirect(url_for('login'))
    
    conn = get_db_connection()
    post = conn.execute('''
        SELECT p.*, u.username as author_name 
        FROM forum_posts p 
        JOIN users u ON p.author_id = u.id 
        WHERE p.id = ?
    ''', (post_id,)).fetchone()
    
    replies = conn.execute('''
        SELECT r.*, u.username as author_name 
        FROM forum_replies r 
        JOIN users u ON r.author_id = u.id 
        WHERE r.post_id = ?
        ORDER BY r.created_at ASC
    ''', (post_id,)).fetchall()
    conn.close()
    
    return render_template('forum_post.html', post=post, replies=replies)

@app.route('/forum/new_post', methods=['GET', 'POST'])
@app.route('/forum/new_post/<category>', methods=['GET', 'POST'])
def new_forum_post(category=None):
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    if request.method == 'POST':
        title = request.form['title']
        content = request.form['content']
        post_category = request.form.get('category', 'general')
        
        conn = get_db_connection()
        conn.execute('''
            INSERT INTO forum_posts (title, content, category, author_id)
            VALUES (?, ?, ?, ?)
        ''', (title, content, post_category, session['user_id']))
        conn.commit()
        conn.close()
        
        flash('Post created successfully!')
        return redirect(url_for('forum', category=post_category))
    
    categories = [
        ('game_items', 'Game Items & Equipment'),
        ('accounts', 'Game Accounts'),
        ('currency', 'Game Currency'),
        ('chat', 'Gaming Chat'),
        ('general', 'General Discussion')
    ]
    
    return render_template('new_forum_post.html', categories=categories, selected_category=category)

@app.route('/forum/reply/<int:post_id>', methods=['POST'])
def forum_reply(post_id):
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    content = request.form['content']
    
    conn = get_db_connection()
    conn.execute('''
        INSERT INTO forum_replies (post_id, content, author_id)
        VALUES (?, ?, ?)
    ''', (post_id, content, session['user_id']))
    conn.commit()
    conn.close()
    
    flash('Reply added successfully!')
    return redirect(url_for('forum_post', post_id=post_id))

@app.route('/pay_posting_fee', methods=['GET', 'POST'])
def pay_posting_fee():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    if request.method == 'POST':
        transaction_id = request.form.get('transaction_id', '').strip()
        
        if transaction_id:
            # In a real application, you would verify the transaction on the blockchain
            # For now, we'll accept any non-empty transaction ID as valid
            conn = get_db_connection()
            conn.execute('''
                UPDATE users SET posting_fee_paid = TRUE 
                WHERE id = ?
            ''', (session['user_id'],))
            conn.commit()
            conn.close()
            
            flash(f'Posting fee payment confirmed! Transaction ID: {transaction_id}. You can now list items.')
            return redirect(url_for('sell_item'))
        else:
            flash('Please provide a valid transaction ID.')
    
    return render_template('pay_posting_fee.html')

if __name__ == '__main__':
    init_db()
    app.run(host='0.0.0.0', port=5000, debug=True)
