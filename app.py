# app.py - Fixed CSRF implementation and session management
from flask import Flask, render_template, request, redirect, url_for, session, jsonify, flash
from flask_wtf.csrf import CSRFProtect, generate_csrf
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from datetime import timedelta
import os

app = Flask(__name__)
app.secret_key = 'supersecretkey'  # Should be a long, random string in production
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///freshveggies.db'
app.config['UPLOAD_FOLDER'] = 'static/uploads'
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(minutes=30)
app.config['WTF_CSRF_ENABLED'] = True
app.config['WTF_CSRF_SECRET_KEY'] = 'anothersecretkey'  # Different from app.secret_key

# Initialize extensions
db = SQLAlchemy(app)
csrf = CSRFProtect(app)  # This must come after app.config is set

# Database Models (unchanged from your original)
class Product(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    price = db.Column(db.Float, nullable=False)
    image = db.Column(db.String(200), nullable=False)
    category = db.Column(db.String(50), nullable=False)
    
    def __repr__(self):
        return f'<Product {self.name}>'

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)
    is_admin = db.Column(db.Boolean, default=False)
    
    def __repr__(self):
        return f'<User {self.username}>'

class CartItem(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    product_id = db.Column(db.Integer, db.ForeignKey('product.id'), nullable=False)
    quantity = db.Column(db.Integer, default=1)
    product = db.relationship('Product', backref='cart_items')
    
    def __repr__(self):
        return f'<CartItem {self.product.name}>'

class Order(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    total = db.Column(db.Float, nullable=False)
    status = db.Column(db.String(20), default='Pending')
    created_at = db.Column(db.DateTime, server_default=db.func.now())
    
    def __repr__(self):
        return f'<Order {self.id}>'

class OrderItem(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    order_id = db.Column(db.Integer, db.ForeignKey('order.id'), nullable=False)
    product_id = db.Column(db.Integer, db.ForeignKey('product.id'), nullable=False)
    quantity = db.Column(db.Integer, nullable=False)
    price = db.Column(db.Float, nullable=False)
    product = db.relationship('Product')
    
    def __repr__(self):
        return f'<OrderItem {self.product.name}>'

class Message(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(100), nullable=False)
    message = db.Column(db.Text, nullable=False)
    created_at = db.Column(db.DateTime, server_default=db.func.now())
    
    def __repr__(self):
        return f'<Message from {self.name}>'

# Create database tables
with app.app_context():
    db.create_all()
    
    # Create admin user if not exists
    if not User.query.filter_by(username='dhruba').first():
        admin_user = User(
            username='dhruba',
            password=generate_password_hash('admin123'),
            is_admin=True
        )
        db.session.add(admin_user)
        db.session.commit()
    
    # Add sample products if none exist
    if not Product.query.first():
        sample_products = [
            {'name': 'Brinjal', 'price': 40, 'image': 'Brinjal.jpg', 'category': 'Vegetables'},
            {'name': 'Carrots', 'price': 30, 'image': 'carrots.jpg', 'category': 'Vegetables'},
            {'name': 'Cauliflower', 'price': 10, 'image': 'coliflower.avif', 'category': 'Vegetables'},
            {'name': 'Tomatoes', 'price': 25, 'image': 'tomatoes.jpg', 'category': 'Vegetables'},
            {'name': 'Long Bean', 'price': 40, 'image': 'LongBean.jpg', 'category': 'Vegetables'},
            {'name': 'Gourd', 'price': 20, 'image': 'Gourd.jpg', 'category': 'Vegetables'},
            {'name': 'Bitter Gourd', 'price': 35, 'image': 'bitter_gourd.jpg', 'category': 'Vegetables'},
            {'name': 'Potato', 'price': 20, 'image': 'potato.jpg', 'category': 'Vegetables'},
            {'name': 'Cabbage', 'price': 20, 'image': 'cabbage.jpg', 'category': 'Vegetables'},
        ]
        
        for product in sample_products:
            new_product = Product(**product)
            db.session.add(new_product)
        
        db.session.commit()

# Inject CSRF token into all templates
@app.context_processor
def inject_csrf_token():
    return dict(csrf_token=generate_csrf)

# Routes
@app.route('/')
def home():
    products = Product.query.all()
    cart_count = 0
    
    if 'user_id' in session:
        user = User.query.get(session['user_id'])
        cart_count = CartItem.query.filter_by(user_id=user.id).count()
    
    return render_template('index.html', products=products, cart_count=cart_count)

@app.route('/search')
def search():
    query = request.args.get('q', '')
    cart_count = 0
    
    if 'user_id' in session:
        user = User.query.get(session['user_id'])
        cart_count = CartItem.query.filter_by(user_id=user.id).count()
    
    if query:
        results = Product.query.filter(Product.name.ilike(f'%{query}%')).all()
    else:
        results = []
    
    return render_template('index.html', products=results, cart_count=cart_count, search_query=query)

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        if not request.form.get('csrf_token'):
            flash('CSRF token missing', 'error')
            return redirect(url_for('login'))
        
        username = request.form['username']
        password = request.form['password']
        
        user = User.query.filter_by(username=username).first()
        
        if user and check_password_hash(user.password, password):
            session['user_id'] = user.id
            session['username'] = user.username
            session['is_admin'] = user.is_admin
            return redirect(url_for('home'))
        else:
            return render_template('login.html', error='Invalid username or password')
    
    return render_template('login.html')

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('home'))

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        if not request.form.get('csrf_token'):
            flash('CSRF token missing', 'error')
            return redirect(url_for('register'))
        
        username = request.form['username']
        password = request.form['password']
        confirm_password = request.form['confirm_password']
        
        if password != confirm_password:
            return render_template('register.html', error='Passwords do not match')
        
        existing_user = User.query.filter_by(username=username).first()
        if existing_user:
            return render_template('register.html', error='Username already exists')
        
        new_user = User(
            username=username,
            password=generate_password_hash(password),
            is_admin=False
        )
        db.session.add(new_user)
        db.session.commit()
        
        session['user_id'] = new_user.id
        session['username'] = new_user.username
        session['is_admin'] = False
        
        return redirect(url_for('home'))
    
    return render_template('register.html')

@app.route('/add_to_cart', methods=['POST'])
@csrf.exempt  # Exempt from CSRF since it's called via AJAX and we validate session
def add_to_cart():
    if 'user_id' not in session:
        return jsonify({'success': False, 'message': 'Please login to add items to cart', 'redirect': url_for('login')})
    
    try:
        product_id = request.form.get('product_id')
        user_id = session['user_id']
        
        # Check if product exists
        product = Product.query.get(product_id)
        if not product:
            return jsonify({'success': False, 'message': 'Product not found'})
        
        # Check if product already in cart
        existing_item = CartItem.query.filter_by(
            user_id=user_id, 
            product_id=product_id
        ).first()
        
        if existing_item:
            existing_item.quantity += 1
        else:
            new_item = CartItem(user_id=user_id, product_id=product_id)
            db.session.add(new_item)
        
        db.session.commit()
        
        # Get updated cart count
        cart_count = CartItem.query.filter_by(user_id=user_id).count()
        
        return jsonify({'success': True, 'cart_count': cart_count})
    
    except Exception as e:
        app.logger.error(f"Error adding to cart: {str(e)}")
        return jsonify({'success': False, 'message': 'Error adding to cart'})

@app.route('/cart')
def view_cart():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    try:
        user_id = session['user_id']
        cart_items = CartItem.query.filter_by(user_id=user_id).all()
        cart_count = CartItem.query.filter_by(user_id=user_id).count()
        
        if not cart_items:
            return render_template('cart.html', cart_items=[], total=0, cart_count=cart_count)
        
        total = sum(item.product.price * item.quantity for item in cart_items)
        return render_template('cart.html', cart_items=cart_items, total=total, cart_count=cart_count)
    
    except Exception as e:
        app.logger.error(f"Error viewing cart: {str(e)}")
        flash("Error loading your cart", "error")
        return redirect(url_for('home'))

@app.route('/remove_from_cart/<int:item_id>')
def remove_from_cart(item_id):
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    item = CartItem.query.get(item_id)
    
    if item and item.user_id == session['user_id']:
        db.session.delete(item)
        db.session.commit()
    
    return redirect(url_for('view_cart'))

@app.route('/checkout', methods=['POST'])
def checkout():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    user = User.query.get(session['user_id'])
    cart_items = CartItem.query.filter_by(user_id=user.id).all()
    
    if not cart_items:
        return redirect(url_for('view_cart'))
    
    # Create order
    total = sum(item.product.price * item.quantity for item in cart_items)
    new_order = Order(user_id=user.id, total=total)
    db.session.add(new_order)
    db.session.commit()
    
    # Add order items
    for item in cart_items:
        order_item = OrderItem(
            order_id=new_order.id,
            product_id=item.product_id,
            quantity=item.quantity,
            price=item.product.price
        )
        db.session.add(order_item)
    
    # Clear cart
    CartItem.query.filter_by(user_id=user.id).delete()
    db.session.commit()
    
    return render_template('order_confirmation.html', order=new_order)

@app.route('/send_message', methods=['POST'])
def send_message():
    if not request.form.get('csrf_token'):
        flash('CSRF token missing', 'error')
        return redirect(url_for('home'))
    
    name = request.form['name']
    email = request.form['email']
    message_text = request.form['message']
    
    new_message = Message(name=name, email=email, message=message_text)
    db.session.add(new_message)
    db.session.commit()
    
    return redirect(url_for('home', _anchor='contact'))

# Admin Routes
@app.route('/admin/login', methods=['GET', 'POST'])
def admin_login():
    if request.method == 'POST':
        if not request.form.get('csrf_token'):
            flash('CSRF token missing', 'error')
            return redirect(url_for('admin_login'))
        
        username = request.form['username']
        password = request.form['password']
        
        user = User.query.filter_by(username=username, is_admin=True).first()
        
        if user and check_password_hash(user.password, password):
            session['user_id'] = user.id
            session['username'] = user.username
            session['is_admin'] = True
            return redirect(url_for('admin_dashboard'))
        else:
            return render_template('admin_login.html', error='Invalid admin credentials')
    
    return render_template('admin_login.html')

@app.route('/admin/dashboard')
def admin_dashboard():
    if 'is_admin' not in session or not session['is_admin']:
        return redirect(url_for('admin_login'))
    
    messages = Message.query.order_by(Message.created_at.desc()).all()
    orders = Order.query.order_by(Order.created_at.desc()).all()
    products = Product.query.all()
    
    return render_template('admin_dashboard.html', messages=messages, orders=orders, products=products)

@app.route('/admin/add_product', methods=['GET', 'POST'])
def add_product():
    if 'is_admin' not in session or not session['is_admin']:
        return redirect(url_for('admin_login'))
    
    if request.method == 'POST':
        if not request.form.get('csrf_token'):
            flash('CSRF token missing', 'error')
            return redirect(url_for('add_product'))
        
        name = request.form['name']
        price = float(request.form['price'])
        category = request.form['category']
        
        # Handle file upload
        image = 'default.jpg'
        if 'image' in request.files:
            image_file = request.files['image']
            if image_file.filename != '':
                filename = secure_filename(image_file.filename)
                image_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
                image_file.save(image_path)
                image = filename
        
        new_product = Product(name=name, price=price, image=image, category=category)
        db.session.add(new_product)
        db.session.commit()
        
        return redirect(url_for('admin_dashboard'))
    
    return render_template('add_product.html')

@app.route('/admin/delete_product/<int:product_id>')
def delete_product(product_id):
    if 'is_admin' not in session or not session['is_admin']:
        return redirect(url_for('admin_login'))
    
    product = Product.query.get(product_id)
    if product:
        db.session.delete(product)
        db.session.commit()
    
    return redirect(url_for('admin_dashboard'))

@app.route('/admin/delete_message/<int:message_id>')
def delete_message(message_id):
    if 'is_admin' not in session or not session['is_admin']:
        return redirect(url_for('admin_login'))
    
    message = Message.query.get(message_id)
    if message:
        db.session.delete(message)
        db.session.commit()
    
    return redirect(url_for('admin_dashboard'))

@app.route('/admin/update_order_status/<int:order_id>', methods=['POST'])
def update_order_status(order_id):
    if 'is_admin' not in session or not session['is_admin']:
        return redirect(url_for('admin_login'))
    
    if not request.form.get('csrf_token'):
        flash('CSRF token missing', 'error')
        return redirect(url_for('admin_dashboard'))
    
    order = Order.query.get(order_id)
    if order:
        new_status = request.form['status']
        order.status = new_status
        db.session.commit()
    
    return redirect(url_for('admin_dashboard'))

if __name__ == '__main__':
    # Create uploads folder if not exists
    if not os.path.exists(app.config['UPLOAD_FOLDER']):
        os.makedirs(app.config['UPLOAD_FOLDER'])
    
    app.run(debug=True)