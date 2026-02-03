<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>BitHash Capital - Admin Dashboard</title>
    
    <!-- Google Fonts -->
    <link rel="preconnect" href="https://fonts.googleapis.com">
    <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
    <link href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700&display=swap" rel="stylesheet">
    
    <!-- Favicon -->
    <link rel="icon" href="https://www.dropbox.com/scl/fi/1dq16nex1borvvknpcwox/circular_dark_background.png?rlkey=sq2ujl2oxxk9vyvg1j7oz0cdb&raw=1" type="image/png">

    <!-- Font Awesome -->
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css">
    
    <style>
        :root {
            --primary: #0f1419;
            --secondary: #1a2332;
            --accent: #f0b90b;
            --accent-dark: #d6a309;
            --text: #ffffff;
            --text-secondary: #a0aec0;
            --success: #48bb78;
            --warning: #ed8936;
            --danger: #f56565;
            --info: #4299e1;
            --border: #2d3748;
            --radius: 8px;
            --shadow: 0 4px 6px -1px rgba(0, 0, 0, 0.1), 0 2px 4px -1px rgba(0, 0, 0, 0.06);
            --shadow-lg: 0 10px 15px -3px rgba(0, 0, 0, 0.1), 0 4px 6px -2px rgba(0, 0, 0, 0.05);
        }
        
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }
        
        body {
            font-family: 'Inter', sans-serif;
            background-color: var(--primary);
            color: var(--text);
            line-height: 1.6;
            overflow-x: hidden;
        }
        
        /* Notification System */
        .notification-container {
            position: fixed;
            top: 20px;
            right: 20px;
            z-index: 10000;
            max-width: 400px;
            width: 100%;
        }
        
        .notification {
            background: var(--secondary);
            border-radius: var(--radius);
            padding: 16px;
            margin-bottom: 10px;
            display: flex;
            align-items: flex-start;
            gap: 12px;
            box-shadow: var(--shadow-lg);
            border-left: 4px solid var(--accent);
            transform: translateX(120%);
            transition: transform 0.3s ease;
        }
        
        .notification.show {
            transform: translateX(0);
        }
        
        .notification-icon {
            font-size: 20px;
            flex-shrink: 0;
        }
        
        .notification-success {
            border-left-color: var(--success);
        }
        
        .notification-error {
            border-left-color: var(--danger);
        }
        
        .notification-warning {
            border-left-color: var(--warning);
        }
        
        .notification-info {
            border-left-color: var(--info);
        }
        
        .notification-content {
            flex: 1;
        }
        
        .notification-title {
            font-weight: 600;
            margin-bottom: 4px;
        }
        
        .notification-message {
            font-size: 14px;
            color: var(--text-secondary);
        }
        
        .notification-close {
            background: none;
            border: none;
            color: var(--text-secondary);
            cursor: pointer;
            font-size: 16px;
            flex-shrink: 0;
        }
        
        /* Loading Overlay */
        .loading-overlay {
            position: fixed;
            top: 0;
            left: 0;
            width: 100%;
            height: 100%;
            background: var(--primary);
            display: flex;
            flex-direction: column;
            justify-content: center;
            align-items: center;
            z-index: 9999;
            transition: opacity 0.5s ease;
        }
        
        .loading-logo {
            width: 80px;
            height: 80px;
            margin-bottom: 20px;
            animation: pulse 2s infinite;
        }
        
        .loading-text {
            font-weight: 600;
            color: var(--text-secondary);
            font-size: 16px;
        }
        
        @keyframes pulse {
            0% { transform: scale(1); }
            50% { transform: scale(1.05); }
            100% { transform: scale(1); }
        }
        
        /* Security Badge */
        .security-badge {
            position: fixed;
            bottom: 20px;
            right: 20px;
            background: var(--secondary);
            padding: 8px 12px;
            border-radius: var(--radius);
            font-size: 12px;
            display: flex;
            align-items: center;
            gap: 8px;
            z-index: 100;
            border: 1px solid var(--border);
        }
        
        .security-badge i {
            color: var(--accent);
        }
        
        /* Header */
        #main-header {
            background: var(--secondary);
            padding: 15px 0;
            border-bottom: 1px solid var(--border);
            position: sticky;
            top: 0;
            z-index: 100;
        }
        
        .header-container {
            display: flex;
            justify-content: space-between;
            align-items: center;
            max-width: 1200px;
            margin: 0 auto;
            padding: 0 20px;
        }
        
        .logo {
            display: flex;
            align-items: center;
            gap: 12px;
            cursor: pointer;
        }
        
        .logo img {
            width: 40px;
            height: 40px;
        }
        
        .logo-text {
            font-size: 24px;
            font-weight: 700;
            color: var(--text);
        }
        
        .bitcoin-animation {
            color: var(--accent);
            display: inline-block;
            animation: bounce 2s infinite;
        }
        
        @keyframes bounce {
            0%, 100% { transform: translateY(0); }
            50% { transform: translateY(-5px); }
        }
        
        .header-actions {
            display: flex;
            align-items: center;
            gap: 15px;
        }
        
        .user-profile {
            display: flex;
            align-items: center;
            gap: 10px;
            cursor: pointer;
            padding: 8px 12px;
            border-radius: var(--radius);
            transition: background 0.3s ease;
        }
        
        .user-profile:hover {
            background: rgba(255, 255, 255, 0.05);
        }
        
        .user-avatar {
            width: 36px;
            height: 36px;
            border-radius: 50%;
            background: var(--accent);
            display: flex;
            align-items: center;
            justify-content: center;
            font-weight: 600;
            color: var(--primary);
        }
        
        .mobile-menu-toggle {
            display: none;
            background: none;
            border: none;
            color: var(--text);
            font-size: 24px;
            cursor: pointer;
        }
        
        /* Login Modal */
        .login-modal {
            position: fixed;
            top: 0;
            left: 0;
            width: 100%;
            height: 100%;
            background: rgba(15, 20, 25, 0.95);
            display: flex;
            justify-content: center;
            align-items: center;
            z-index: 2000;
        }
        
        .login-container {
            background: var(--secondary);
            padding: 40px;
            border-radius: var(--radius);
            width: 100%;
            max-width: 450px;
            box-shadow: var(--shadow);
            border: 1px solid var(--border);
        }
        
        .login-header {
            text-align: center;
            margin-bottom: 30px;
        }
        
        .login-header h2 {
            font-weight: 700;
            font-size: 28px;
            margin-bottom: 10px;
        }
        
        .login-header p {
            color: var(--text-secondary);
            font-size: 14px;
        }
        
        .form-group {
            margin-bottom: 20px;
        }
        
        .form-group label {
            display: block;
            margin-bottom: 8px;
            font-weight: 500;
            font-size: 14px;
        }
        
        .form-control {
            width: 100%;
            padding: 12px 15px;
            background: var(--primary);
            border: 1px solid var(--border);
            border-radius: var(--radius);
            color: var(--text);
            font-size: 16px;
            transition: all 0.3s ease;
        }
        
        .form-control:focus {
            outline: none;
            border-color: var(--accent);
            box-shadow: 0 0 0 3px rgba(240, 185, 11, 0.1);
        }
        
        .btn {
            display: inline-flex;
            align-items: center;
            justify-content: center;
            gap: 8px;
            padding: 12px 24px;
            border: none;
            border-radius: var(--radius);
            font-weight: 600;
            font-size: 16px;
            cursor: pointer;
            transition: all 0.3s ease;
        }
        
        .btn-primary {
            background: var(--accent);
            color: var(--primary);
            width: 100%;
        }
        
        .btn-primary:hover {
            background: var(--accent-dark);
        }
        
        .btn-secondary {
            background: var(--border);
            color: var(--text);
        }
        
        .btn-secondary:hover {
            background: #3a475c;
        }
        
        .btn-success {
            background: var(--success);
            color: white;
        }
        
        .btn-success:hover {
            background: #38a169;
        }
        
        .btn-danger {
            background: var(--danger);
            color: white;
        }
        
        .btn-danger:hover {
            background: #e53e3e;
        }
        
        .btn-info {
            background: var(--info);
            color: white;
        }
        
        .btn-info:hover {
            background: #3182ce;
        }
        
        /* Admin Dashboard */
        .admin-dashboard {
            display: none;
            max-width: 1200px;
            margin: 40px auto;
            padding: 0 20px;
        }
        
        .dashboard-header {
            margin-bottom: 30px;
        }
        
        .dashboard-header h1 {
            font-weight: 700;
            font-size: 32px;
            margin-bottom: 10px;
        }
        
        .dashboard-header p {
            color: var(--text-secondary);
        }
        
        .stats-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
            gap: 20px;
            margin-bottom: 30px;
        }
        
        .stat-card {
            background: var(--secondary);
            padding: 20px;
            border-radius: var(--radius);
            border: 1px solid var(--border);
            transition: transform 0.3s ease, box-shadow 0.3s ease;
        }
        
        .stat-card:hover {
            transform: translateY(-5px);
            box-shadow: var(--shadow-lg);
        }
        
        .stat-card h3 {
            font-size: 14px;
            color: var(--text-secondary);
            margin-bottom: 10px;
            text-transform: uppercase;
            letter-spacing: 0.5px;
        }
        
        .stat-value {
            font-size: 28px;
            font-weight: 700;
            color: var(--accent);
        }
        
        .stat-trend {
            display: flex;
            align-items: center;
            gap: 5px;
            margin-top: 8px;
            font-size: 14px;
        }
        
        .trend-up {
            color: var(--success);
        }
        
        .trend-down {
            color: var(--danger);
        }
        
        .dashboard-tabs {
            display: flex;
            gap: 10px;
            margin-bottom: 20px;
            border-bottom: 1px solid var(--border);
            padding-bottom: 10px;
            flex-wrap: wrap;
        }
        
        .tab-btn {
            background: none;
            border: none;
            padding: 10px 20px;
            color: var(--text-secondary);
            font-weight: 500;
            cursor: pointer;
            border-radius: var(--radius) var(--radius) 0 0;
            transition: all 0.3s ease;
        }
        
        .tab-btn.active {
            color: var(--accent);
            background: var(--secondary);
            border-bottom: 2px solid var(--accent);
        }
        
        .tab-content {
            display: none;
        }
        
        .tab-content.active {
            display: block;
        }
        
        .card {
            background: var(--secondary);
            border-radius: var(--radius);
            border: 1px solid var(--border);
            padding: 25px;
            margin-bottom: 20px;
        }
        
        .card-header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 20px;
        }
        
        .card-title {
            font-size: 20px;
            font-weight: 600;
        }
        
        .form-row {
            display: flex;
            gap: 15px;
            margin-bottom: 15px;
        }
        
        .form-row .form-group {
            flex: 1;
            margin-bottom: 0;
        }
        
        .email-preview {
            background: var(--primary);
            border: 1px solid var(--border);
            border-radius: var(--radius);
            padding: 15px;
            margin-top: 20px;
            min-height: 200px;
        }
        
        .investor-list {
            max-height: 400px;
            overflow-y: auto;
        }
        
        .investor-item {
            display: flex;
            justify-content: space-between;
            align-items: center;
            padding: 12px 15px;
            border-bottom: 1px solid var(--border);
            transition: background 0.3s ease;
        }
        
        .investor-item:hover {
            background: rgba(255, 255, 255, 0.02);
        }
        
        .investor-info h4 {
            font-weight: 600;
            margin-bottom: 5px;
        }
        
        .investor-info p {
            color: var(--text-secondary);
            font-size: 14px;
        }
        
        .investor-actions {
            display: flex;
            gap: 10px;
        }
        
        .status-badge {
            display: inline-flex;
            align-items: center;
            gap: 5px;
            padding: 4px 10px;
            border-radius: 20px;
            font-size: 12px;
            font-weight: 600;
        }
        
        .status-sent {
            background: rgba(72, 187, 120, 0.2);
            color: var(--success);
        }
        
        .status-opened {
            background: rgba(237, 137, 54, 0.2);
            color: var(--warning);
        }
        
        .status-failed {
            background: rgba(245, 101, 101, 0.2);
            color: var(--danger);
        }
        
        .table-container {
            overflow-x: auto;
        }
        
        table {
            width: 100%;
            border-collapse: collapse;
        }
        
        th, td {
            padding: 12px 15px;
            text-align: left;
            border-bottom: 1px solid var(--border);
        }
        
        th {
            font-weight: 600;
            color: var(--text-secondary);
            font-size: 14px;
        }
        
        .pagination {
            display: flex;
            justify-content: center;
            gap: 10px;
            margin-top: 20px;
        }
        
        .page-btn {
            background: var(--secondary);
            border: 1px solid var(--border);
            color: var(--text);
            width: 40px;
            height: 40px;
            border-radius: var(--radius);
            display: flex;
            align-items: center;
            justify-content: center;
            cursor: pointer;
            transition: all 0.3s ease;
        }
        
        .page-btn.active {
            background: var(--accent);
            color: var(--primary);
            border-color: var(--accent);
        }
        
        .page-btn:hover:not(.active) {
            background: var(--border);
        }
        
        .alert {
            padding: 15px;
            border-radius: var(--radius);
            margin-bottom: 20px;
            display: flex;
            align-items: center;
            gap: 10px;
        }
        
        .alert-success {
            background: rgba(72, 187, 120, 0.2);
            border: 1px solid var(--success);
            color: var(--success);
        }
        
        .alert-error {
            background: rgba(245, 101, 101, 0.2);
            border: 1px solid var(--danger);
            color: var(--danger);
        }
        
        .alert-warning {
            background: rgba(237, 137, 54, 0.2);
            border: 1px solid var(--warning);
            color: var(--warning);
        }
        
        /* Modal System */
        .modal-overlay {
            position: fixed;
            top: 0;
            left: 0;
            width: 100%;
            height: 100%;
            background: rgba(15, 20, 25, 0.8);
            display: flex;
            justify-content: center;
            align-items: center;
            z-index: 2000;
            opacity: 0;
            visibility: hidden;
            transition: opacity 0.3s ease, visibility 0.3s ease;
        }
        
        .modal-overlay.active {
            opacity: 1;
            visibility: visible;
        }
        
        .modal {
            background: var(--secondary);
            border-radius: var(--radius);
            width: 90%;
            max-width: 600px;
            max-height: 90vh;
            overflow-y: auto;
            box-shadow: var(--shadow-lg);
            border: 1px solid var(--border);
            transform: translateY(20px);
            transition: transform 0.3s ease;
        }
        
        .modal-overlay.active .modal {
            transform: translateY(0);
        }
        
        .modal-header {
            padding: 20px 25px;
            border-bottom: 1px solid var(--border);
            display: flex;
            justify-content: space-between;
            align-items: center;
        }
        
        .modal-title {
            font-size: 20px;
            font-weight: 600;
        }
        
        .modal-close {
            background: none;
            border: none;
            color: var(--text-secondary);
            font-size: 20px;
            cursor: pointer;
            transition: color 0.3s ease;
        }
        
        .modal-close:hover {
            color: var(--text);
        }
        
        .modal-body {
            padding: 25px;
        }
        
        .modal-footer {
            padding: 20px 25px;
            border-top: 1px solid var(--border);
            display: flex;
            justify-content: flex-end;
            gap: 10px;
        }
        
        /* Template Selection */
        .template-grid {
            display: grid;
            grid-template-columns: repeat(auto-fill, minmax(300px, 1fr));
            gap: 20px;
            margin-top: 20px;
        }
        
        .template-card {
            background: var(--primary);
            border: 1px solid var(--border);
            border-radius: var(--radius);
            padding: 20px;
            cursor: pointer;
            transition: all 0.3s ease;
        }
        
        .template-card:hover {
            border-color: var(--accent);
            transform: translateY(-2px);
        }
        
        .template-card.selected {
            border-color: var(--accent);
            background: rgba(240, 185, 11, 0.1);
        }
        
        .template-name {
            font-weight: 600;
            margin-bottom: 10px;
            color: var(--text);
        }
        
        .template-subject {
            color: var(--text-secondary);
            font-size: 14px;
            margin-bottom: 10px;
        }
        
        .template-category {
            display: inline-block;
            background: var(--border);
            padding: 4px 8px;
            border-radius: 12px;
            font-size: 12px;
            color: var(--text-secondary);
        }
        
        /* Recipient Selection */
        .recipient-section {
            margin-bottom: 20px;
            padding: 15px;
            background: var(--primary);
            border-radius: var(--radius);
            border: 1px solid var(--border);
        }
        
        .recipient-tags {
            display: flex;
            flex-wrap: wrap;
            gap: 8px;
            margin-top: 10px;
        }
        
        .recipient-tag {
            background: var(--accent);
            color: var(--primary);
            padding: 4px 8px;
            border-radius: 12px;
            font-size: 12px;
            display: flex;
            align-items: center;
            gap: 5px;
        }
        
        .recipient-tag .remove {
            cursor: pointer;
            font-weight: bold;
        }
        
        /* Excel Upload */
        .excel-upload {
            border: 2px dashed var(--border);
            border-radius: var(--radius);
            padding: 30px;
            text-align: center;
            margin-bottom: 20px;
            transition: all 0.3s ease;
        }
        
        .excel-upload:hover {
            border-color: var(--accent);
        }
        
        .excel-upload i {
            font-size: 48px;
            color: var(--text-secondary);
            margin-bottom: 15px;
        }
        
        .excel-upload p {
            color: var(--text-secondary);
            margin-bottom: 15px;
        }
        
        .file-input {
            display: none;
        }
        
        .file-label {
            display: inline-block;
            background: var(--accent);
            color: var(--primary);
            padding: 10px 20px;
            border-radius: var(--radius);
            cursor: pointer;
            font-weight: 600;
            transition: background 0.3s ease;
        }
        
        .file-label:hover {
            background: var(--accent-dark);
        }
        
        .uploaded-files {
            margin-top: 15px;
        }
        
        .uploaded-file {
            display: flex;
            justify-content: space-between;
            align-items: center;
            background: var(--primary);
            padding: 10px 15px;
            border-radius: var(--radius);
            margin-bottom: 10px;
        }
        
        .file-info {
            display: flex;
            align-items: center;
            gap: 10px;
        }
        
        .file-name {
            font-weight: 500;
        }
        
        .file-size {
            color: var(--text-secondary);
            font-size: 12px;
        }
        
        .file-remove {
            background: none;
            border: none;
            color: var(--danger);
            cursor: pointer;
        }
        
        /* Responsive */
        @media (max-width: 768px) {
            .mobile-menu-toggle {
                display: block;
            }
            
            .form-row {
                flex-direction: column;
                gap: 15px;
            }
            
            .stats-grid {
                grid-template-columns: 1fr;
            }
            
            .dashboard-tabs {
                flex-wrap: wrap;
            }
            
            .header-container {
                padding: 0 15px;
            }
            
            .admin-dashboard {
                padding: 0 15px;
            }
            
            .login-container {
                padding: 30px 20px;
                margin: 0 15px;
            }
            
            .notification-container {
                max-width: calc(100% - 30px);
                right: 15px;
            }
            
            .template-grid {
                grid-template-columns: 1fr;
            }
        }
    </style>
</head>
<body>
    <!-- Notification Container -->
    <div class="notification-container" id="notification-container"></div>
    
    <!-- Loading Overlay -->
    <div class="loading-overlay" id="loading-overlay">
        <img src="https://www.dropbox.com/scl/fi/1dq16nex1borvvknpcwox/circular_dark_background.png?rlkey=sq2ujl2oxxk9vyvg1j7oz0cdb&raw=1" alt="BitHash Logo" class="loading-logo">    
        <div class="loading-text">Establishing Secure Connection</div>
    </div>

    <!-- Security Badge -->
    <div class="security-badge">
        <i class="fas fa-shield-alt"></i>
        <span>256-bit AES & TLS 1.3 Encrypted</span>
    </div>
    
    <!-- Enhanced Header -->
    <header id="main-header">
        <div class="container header-container">
            <div class="logo" onclick="window.location.href='index.html'">
                <img src="https://www.dropbox.com/scl/fi/1dq16nex1borvvknpcwox/circular_dark_background.png?rlkey=sq2ujl2oxxk9vyvg1j7oz0cdb&raw=1" alt="BitHash Logo">
                <span class="logo-text">
                    <span class="bitcoin-animation">₿</span>itHash Capital Admin
                </span>
            </div>
            
            <div class="header-actions" id="header-actions" style="display: none;">
                <div class="user-profile" id="user-profile">
                    <div class="user-avatar" id="user-avatar">A</div>
                    <span id="user-name">Admin</span>
                    <i class="fas fa-chevron-down"></i>
                </div>
            </div>
            
            <button class="mobile-menu-toggle" id="mobile-menu-toggle" aria-label="Toggle navigation">
                <i class="fas fa-bars"></i>
            </button>
        </div>
    </header>
    
    <!-- Login Modal -->
    <div class="login-modal" id="login-modal">
        <div class="login-container">
            <div class="login-header">
                <h2>Admin Access</h2>
                <p>Secure authentication required</p>
            </div>
            <form id="login-form">
                <div class="form-group">
                    <label for="username">Username</label>
                    <input type="text" id="username" class="form-control" required>
                </div>
                <div class="form-group">
                    <label for="password">Password</label>
                    <input type="password" id="password" class="form-control" required>
                </div>
                <button type="submit" class="btn btn-primary">
                    <i class="fas fa-lock"></i> Authenticate
                </button>
            </form>
        </div>
    </div>
    
    <!-- Admin Dashboard -->
    <div class="admin-dashboard" id="admin-dashboard">
        <div class="dashboard-header">
            <h1>Email Management</h1>
            <p>Send emails to investors and track engagement</p>
        </div>
        
        <div class="stats-grid">
            <div class="stat-card">
                <h3>Total Investors</h3>
                <div class="stat-value" id="total-investors">0</div>
                <div class="stat-trend trend-up">
                    <i class="fas fa-arrow-up"></i>
                    <span id="investor-trend">0%</span>
                </div>
            </div>
            <div class="stat-card">
                <h3>Emails Sent</h3>
                <div class="stat-value" id="emails-sent">0</div>
                <div class="stat-trend trend-up">
                    <i class="fas fa-arrow-up"></i>
                    <span id="email-trend">0%</span>
                </div>
            </div>
            <div class="stat-card">
                <h3>Open Rate</h3>
                <div class="stat-value" id="open-rate">0%</div>
                <div class="stat-trend trend-down">
                    <i class="fas fa-arrow-down"></i>
                    <span id="open-trend">0%</span>
                </div>
            </div>
            <div class="stat-card">
                <h3>Last Activity</h3>
                <div class="stat-value" id="last-activity">-</div>
                <div class="stat-trend">
                    <i class="fas fa-clock"></i>
                    <span id="activity-time">Just now</span>
                </div>
            </div>
        </div>
        
        <div class="dashboard-tabs">
            <button class="tab-btn active" data-tab="send-email">Send Email</button>
            <button class="tab-btn" data-tab="investors">Investors</button>
            <button class="tab-btn" data-tab="email-history">Email History</button>
            <button class="tab-btn" data-tab="templates">Templates</button>
            <button class="tab-btn" data-tab="analytics">Analytics</button>
        </div>
        
        <!-- Send Email Tab -->
        <div class="tab-content active" id="send-email">
            <div class="card">
                <div class="card-header">
                    <h3 class="card-title">Compose Email</h3>
                    <div>
                        <button class="btn btn-secondary" id="load-template-btn">
                            <i class="fas fa-file-alt"></i> Load Template
                        </button>
                    </div>
                </div>
                
                <div class="form-group">
                    <label for="recipient-type">Send To</label>
                    <select id="recipient-type" class="form-control">
                        <option value="all">All Investors</option>
                        <option value="selected">Selected Investors</option>
                        <option value="manual">Manual Email Addresses</option>
                        <option value="excel">Upload Excel File</option>
                    </select>
                </div>
                
                <!-- Selected Investors Section -->
                <div id="selected-investors-section" class="recipient-section" style="display: none;">
                    <label>Select Investors</label>
                    <select id="investor-select" class="form-control" multiple style="height: 150px;">
                        <option value="">Loading investors...</option>
                    </select>
                    <div class="recipient-tags" id="selected-investors-tags"></div>
                </div>
                
                <!-- Manual Emails Section -->
                <div id="manual-emails-section" class="recipient-section" style="display: none;">
                    <label>Enter Email Addresses (one per line or comma separated)</label>
                    <textarea id="manual-emails" class="form-control" rows="4" placeholder="Enter email addresses..."></textarea>
                    <div class="recipient-tags" id="manual-emails-tags"></div>
                </div>
                
                <!-- Excel Upload Section -->
                <div id="excel-upload-section" class="recipient-section" style="display: none;">
                    <div class="excel-upload" id="excel-dropzone">
                        <i class="fas fa-file-excel"></i>
                        <p>Upload Excel file containing email addresses</p>
                        <input type="file" id="excel-file" class="file-input" accept=".xlsx, .xls">
                        <label for="excel-file" class="file-label">
                            <i class="fas fa-upload"></i> Choose Excel File
                        </label>
                    </div>
                    <div class="uploaded-files" id="uploaded-files"></div>
                    <div id="excel-preview" style="display: none;">
                        <h4>Email Preview from Excel</h4>
                        <div id="excel-emails-preview" class="recipient-tags"></div>
                    </div>
                </div>
                
                <div class="form-group">
                    <label for="email-subject">Subject</label>
                    <input type="text" id="email-subject" class="form-control" placeholder="Enter email subject">
                </div>
                
                <div class="form-group">
                    <label for="email-content">Email Content</label>
                    <textarea id="email-content" class="form-control" rows="10" placeholder="Compose your email here..."></textarea>
                </div>
                
                <div class="form-row">
                    <div class="form-group">
                        <label for="tracking-enabled">
                            <input type="checkbox" id="tracking-enabled" checked> Enable Open Tracking
                        </label>
                    </div>
                    <div class="form-group">
                        <label for="schedule-enabled">
                            <input type="checkbox" id="schedule-enabled"> Schedule Email
                        </label>
                    </div>
                    <div class="form-group">
                        <label for="save-template">
                            <input type="checkbox" id="save-template"> Save as Template
                        </label>
                    </div>
                </div>
                
                <div id="schedule-section" style="display: none;">
                    <div class="form-group">
                        <label for="schedule-date">Schedule Date & Time</label>
                        <input type="datetime-local" id="schedule-date" class="form-control">
                    </div>
                </div>
                
                <div id="template-section" style="display: none;">
                    <div class="form-group">
                        <label for="template-name">Template Name</label>
                        <input type="text" id="template-name" class="form-control" placeholder="Enter template name">
                    </div>
                </div>
                
                <div class="email-preview">
                    <h4>Preview</h4>
                    <div id="email-preview-content">
                        Email preview will appear here...
                    </div>
                </div>
                
                <div style="margin-top: 20px; display: flex; gap: 10px;">
                    <button class="btn btn-primary" id="send-email-btn">
                        <i class="fas fa-paper-plane"></i> Send Email
                    </button>
                    <button class="btn btn-info" id="preview-email-btn">
                        <i class="fas fa-eye"></i> Preview
                    </button>
                </div>
            </div>
        </div>
        
        <!-- Investors Tab -->
        <div class="tab-content" id="investors">
            <div class="card">
                <div class="card-header">
                    <h3 class="card-title">Investor List</h3>
                    <div style="display: flex; gap: 10px;">
                        <button class="btn btn-secondary" id="refresh-investors">
                            <i class="fas fa-sync-alt"></i> Refresh
                        </button>
                        <button class="btn btn-info" id="export-investors">
                            <i class="fas fa-download"></i> Export
                        </button>
                    </div>
                </div>
                
                <div class="form-row">
                    <div class="form-group">
                        <input type="text" id="investor-search" class="form-control" placeholder="Search investors...">
                    </div>
                    <div class="form-group">
                        <select id="investor-filter" class="form-control">
                            <option value="">All Status</option>
                            <option value="active">Active</option>
                            <option value="inactive">Inactive</option>
                            <option value="new">New</option>
                        </select>
                    </div>
                </div>
                
                <div class="table-container">
                    <table>
                        <thead>
                            <tr>
                                <th>Name</th>
                                <th>Email</th>
                                <th>Join Date</th>
                                <th>Tier</th>
                                <th>Status</th>
                                <th>Total Invested</th>
                            </tr>
                        </thead>
                        <tbody id="investor-table">
                            <!-- Investor data will be populated here -->
                        </tbody>
                    </table>
                </div>
                
                <div class="pagination" id="investor-pagination">
                    <!-- Pagination will be populated here -->
                </div>
            </div>
        </div>
        
        <!-- Email History Tab -->
        <div class="tab-content" id="email-history">
            <div class="card">
                <div class="card-header">
                    <h3 class="card-title">Email History</h3>
                    <div style="display: flex; gap: 10px;">
                        <button class="btn btn-secondary" id="refresh-emails">
                            <i class="fas fa-sync-alt"></i> Refresh
                        </button>
                        <button class="btn btn-info" id="export-emails">
                            <i class="fas fa-download"></i> Export
                        </button>
                    </div>
                </div>
                
                <div class="form-row">
                    <div class="form-group">
                        <input type="text" id="email-search" class="form-control" placeholder="Search emails...">
                    </div>
                    <div class="form-group">
                        <select id="email-filter" class="form-control">
                            <option value="">All Status</option>
                            <option value="sent">Sent</option>
                            <option value="scheduled">Scheduled</option>
                            <option value="failed">Failed</option>
                        </select>
                    </div>
                </div>
                
                <div class="table-container">
                    <table>
                        <thead>
                            <tr>
                                <th>Subject</th>
                                <th>Recipients</th>
                                <th>Sent Date</th>
                                <th>Open Rate</th>
                                <th>Status</th>
                                <th>Sent By</th>
                            </tr>
                        </thead>
                        <tbody id="email-history-table">
                            <!-- Email history will be populated here -->
                        </tbody>
                    </table>
                </div>
                
                <div class="pagination" id="email-pagination">
                    <!-- Pagination will be populated here -->
                </div>
            </div>
        </div>
        
        <!-- Templates Tab -->
        <div class="tab-content" id="templates">
            <div class="card">
                <div class="card-header">
                    <h3 class="card-title">Email Templates</h3>
                    <button class="btn btn-primary" id="create-template-btn">
                        <i class="fas fa-plus"></i> Create Template
                    </button>
                </div>
                
                <div class="form-group">
                    <input type="text" id="template-search" class="form-control" placeholder="Search templates...">
                </div>
                
                <div class="table-container">
                    <table>
                        <thead>
                            <tr>
                                <th>Template Name</th>
                                <th>Subject</th>
                                <th>Category</th>
                                <th>Last Modified</th>
                                <th>Used</th>
                                <th>Actions</th>
                            </tr>
                        </thead>
                        <tbody id="template-table">
                            <!-- Templates will be populated here -->
                        </tbody>
                    </table>
                </div>
                
                <div class="pagination" id="template-pagination">
                    <!-- Pagination will be populated here -->
                </div>
            </div>
        </div>
        
        <!-- Analytics Tab -->
        <div class="tab-content" id="analytics">
            <div class="card">
                <div class="card-header">
                    <h3 class="card-title">Email Analytics</h3>
                    <div style="display: flex; gap: 10px;">
                        <select id="analytics-period" class="form-control" style="width: auto;">
                            <option value="7">Last 7 days</option>
                            <option value="30">Last 30 days</option>
                            <option value="90">Last 90 days</option>
                            <option value="365">Last year</option>
                        </select>
                    </div>
                </div>
                
                <div class="stats-grid">
                    <div class="stat-card">
                        <h3>Delivery Rate</h3>
                        <div class="stat-value" id="delivery-rate">0%</div>
                        <div class="stat-trend trend-up">
                            <i class="fas fa-arrow-up"></i>
                            <span id="delivery-trend">0%</span>
                        </div>
                    </div>
                    <div class="stat-card">
                        <h3>Open Rate</h3>
                        <div class="stat-value" id="analytics-open-rate">0%</div>
                        <div class="stat-trend trend-down">
                            <i class="fas fa-arrow-down"></i>
                            <span id="analytics-open-trend">0%</span>
                        </div>
                    </div>
                    <div class="stat-card">
                        <h3>Total Sent</h3>
                        <div class="stat-value" id="total-sent">0</div>
                        <div class="stat-trend trend-up">
                            <i class="fas fa-arrow-up"></i>
                            <span id="sent-trend">0%</span>
                        </div>
                    </div>
                    <div class="stat-card">
                        <h3>Unique Opens</h3>
                        <div class="stat-value" id="unique-opens">0</div>
                        <div class="stat-trend trend-up">
                            <i class="fas fa-arrow-up"></i>
                            <span id="opens-trend">0%</span>
                        </div>
                    </div>
                </div>
            </div>
        </div>
    </div>
    
    <!-- Email Preview Modal -->
    <div class="modal-overlay" id="email-preview-modal">
        <div class="modal">
            <div class="modal-header">
                <h3 class="modal-title">Email Preview</h3>
                <button class="modal-close" id="close-preview-modal">
                    <i class="fas fa-times"></i>
                </button>
            </div>
            <div class="modal-body">
                <div id="email-preview-modal-content">
                    Email preview content will appear here
                </div>
            </div>
            <div class="modal-footer">
                <button class="btn btn-secondary" id="close-preview-btn">Close</button>
                <button class="btn btn-primary" id="send-from-preview-btn">Send Email</button>
            </div>
        </div>
    </div>
    
    <!-- Template Modal -->
    <div class="modal-overlay" id="template-modal">
        <div class="modal">
            <div class="modal-header">
                <h3 class="modal-title" id="template-modal-title">Create Template</h3>
                <button class="modal-close" id="close-template-modal">
                    <i class="fas fa-times"></i>
                </button>
            </div>
            <div class="modal-body">
                <div class="form-group">
                    <label for="modal-template-name">Template Name</label>
                    <input type="text" id="modal-template-name" class="form-control" placeholder="Enter template name">
                </div>
                <div class="form-group">
                    <label for="modal-template-subject">Subject</label>
                    <input type="text" id="modal-template-subject" class="form-control" placeholder="Enter email subject">
                </div>
                <div class="form-group">
                    <label for="modal-template-content">Content</label>
                    <textarea id="modal-template-content" class="form-control" rows="10" placeholder="Enter template content"></textarea>
                </div>
            </div>
            <div class="modal-footer">
                <button class="btn btn-secondary" id="cancel-template-btn">Cancel</button>
                <button class="btn btn-primary" id="save-template-btn">Save Template</button>
            </div>
        </div>
    </div>

    <script>
        // API Base URL
        const API_BASE_URL = 'https://hashvex-technologies-backend.onrender.com';
        
        // Global variables
        let authToken = null;
        let currentUser = null;
        let investors = [];
        let emailHistory = [];
        let templates = [];
        let analyticsData = {};
        let currentInvestorPage = 1;
        let currentEmailPage = 1;
        let currentTemplatePage = 1;
        const itemsPerPage = 10;
        let excelEmails = [];
        
        // DOM Elements
        const loadingOverlay = document.getElementById('loading-overlay');
        const loginModal = document.getElementById('login-modal');
        const adminDashboard = document.getElementById('admin-dashboard');
        const loginForm = document.getElementById('login-form');
        const headerActions = document.getElementById('header-actions');
        const userProfile = document.getElementById('user-profile');
        const userAvatar = document.getElementById('user-avatar');
        const userName = document.getElementById('user-name');
        const tabBtns = document.querySelectorAll('.tab-btn');
        const tabContents = document.querySelectorAll('.tab-content');
        const recipientType = document.getElementById('recipient-type');
        const selectedInvestorsSection = document.getElementById('selected-investors-section');
        const manualEmailsSection = document.getElementById('manual-emails-section');
        const excelUploadSection = document.getElementById('excel-upload-section');
        const investorSelect = document.getElementById('investor-select');
        const manualEmails = document.getElementById('manual-emails');
        const excelFile = document.getElementById('excel-file');
        const selectedInvestorsTags = document.getElementById('selected-investors-tags');
        const manualEmailsTags = document.getElementById('manual-emails-tags');
        const excelEmailsPreview = document.getElementById('excel-emails-preview');
        const excelPreview = document.getElementById('excel-preview');
        const emailSubject = document.getElementById('email-subject');
        const emailContent = document.getElementById('email-content');
        const trackingEnabled = document.getElementById('tracking-enabled');
        const scheduleEnabled = document.getElementById('schedule-enabled');
        const scheduleSection = document.getElementById('schedule-section');
        const saveTemplate = document.getElementById('save-template');
        const templateSection = document.getElementById('template-section');
        const templateName = document.getElementById('template-name');
        const emailPreview = document.getElementById('email-preview-content');
        const sendEmailBtn = document.getElementById('send-email-btn');
        const previewEmailBtn = document.getElementById('preview-email-btn');
        const loadTemplateBtn = document.getElementById('load-template-btn');
        
        // Modals
        const emailPreviewModal = document.getElementById('email-preview-modal');
        const closePreviewModal = document.getElementById('close-preview-modal');
        const closePreviewBtn = document.getElementById('close-preview-btn');
        const sendFromPreviewBtn = document.getElementById('send-from-preview-btn');
        const emailPreviewModalContent = document.getElementById('email-preview-modal-content');
        
        const templateModal = document.getElementById('template-modal');
        const closeTemplateModal = document.getElementById('close-template-modal');
        const cancelTemplateBtn = document.getElementById('cancel-template-btn');
        const saveTemplateBtn = document.getElementById('save-template-btn');
        const modalTemplateName = document.getElementById('modal-template-name');
        const modalTemplateSubject = document.getElementById('modal-template-subject');
        const modalTemplateContent = document.getElementById('modal-template-content');
        const templateModalTitle = document.getElementById('template-modal-title');
        
        // Event Listeners
        document.addEventListener('DOMContentLoaded', function() {
            // Simulate loading
            setTimeout(() => {
                loadingOverlay.style.opacity = '0';
                setTimeout(() => {
                    loadingOverlay.style.display = 'none';
                }, 500);
            }, 1500);
            
            // Tab switching
            tabBtns.forEach(btn => {
                btn.addEventListener('click', () => {
                    const tabId = btn.getAttribute('data-tab');
                    
                    // Update active tab button
                    tabBtns.forEach(b => b.classList.remove('active'));
                    btn.classList.add('active');
                    
                    // Update active tab content
                    tabContents.forEach(content => {
                        content.classList.remove('active');
                        if (content.id === tabId) {
                            content.classList.add('active');
                            
                            // Load data for specific tabs when activated
                            if (tabId === 'investors') {
                                fetchInvestors();
                            } else if (tabId === 'email-history') {
                                fetchEmailHistory();
                            } else if (tabId === 'templates') {
                                fetchTemplates();
                            } else if (tabId === 'analytics') {
                                fetchAnalytics();
                            }
                        }
                    });
                });
            });
            
            // Recipient type change
            recipientType.addEventListener('change', function() {
                const value = this.value;
                
                selectedInvestorsSection.style.display = 'none';
                manualEmailsSection.style.display = 'none';
                excelUploadSection.style.display = 'none';
                
                if (value === 'selected') {
                    selectedInvestorsSection.style.display = 'block';
                    fetchAllInvestors();
                } else if (value === 'manual') {
                    manualEmailsSection.style.display = 'block';
                } else if (value === 'excel') {
                    excelUploadSection.style.display = 'block';
                }
            });
            
            // Investor selection
            investorSelect.addEventListener('change', function() {
                updateSelectedInvestorsTags();
            });
            
            // Manual emails input
            manualEmails.addEventListener('input', function() {
                updateManualEmailsTags();
            });
            
            // Excel file upload
            excelFile.addEventListener('change', handleExcelUpload);
            
            // Schedule toggle
            scheduleEnabled.addEventListener('change', function() {
                scheduleSection.style.display = this.checked ? 'block' : 'none';
            });
            
            // Save template toggle
            saveTemplate.addEventListener('change', function() {
                templateSection.style.display = this.checked ? 'block' : 'none';
            });
            
            // Email content preview
            emailContent.addEventListener('input', updateEmailPreview);
            
            // Login form submission
            loginForm.addEventListener('submit', handleLogin);
            
            // Send email
            sendEmailBtn.addEventListener('click', sendEmail);
            
            // Preview email
            previewEmailBtn.addEventListener('click', showEmailPreview);
            
            // Load template
            loadTemplateBtn.addEventListener('click', showLoadTemplateModal);
            
            // Close preview modal
            closePreviewModal.addEventListener('click', hideEmailPreview);
            closePreviewBtn.addEventListener('click', hideEmailPreview);
            
            // Send from preview
            sendFromPreviewBtn.addEventListener('click', sendEmailFromPreview);
            
            // Close template modal
            closeTemplateModal.addEventListener('click', hideTemplateModal);
            cancelTemplateBtn.addEventListener('click', hideTemplateModal);
            
            // Save template
            saveTemplateBtn.addEventListener('click', saveTemplateHandler);
        });
        
        // Utility Functions
        function debounce(func, wait) {
            let timeout;
            return function executedFunction(...args) {
                const later = () => {
                    clearTimeout(timeout);
                    func(...args);
                };
                clearTimeout(timeout);
                timeout = setTimeout(later, wait);
            };
        }
        
        function showNotification(type, title, message, duration = 5000) {
            const notificationContainer = document.getElementById('notification-container');
            const notification = document.createElement('div');
            notification.className = `notification notification-${type}`;
            
            let icon = 'fa-info-circle';
            if (type === 'success') icon = 'fa-check-circle';
            else if (type === 'error') icon = 'fa-exclamation-circle';
            else if (type === 'warning') icon = 'fa-exclamation-triangle';
            
            notification.innerHTML = `
                <div class="notification-icon">
                    <i class="fas ${icon}"></i>
                </div>
                <div class="notification-content">
                    <div class="notification-title">${title}</div>
                    <div class="notification-message">${message}</div>
                </div>
                <button class="notification-close">
                    <i class="fas fa-times"></i>
                </button>
            `;
            
            notificationContainer.appendChild(notification);
            
            // Show notification with animation
            setTimeout(() => {
                notification.classList.add('show');
            }, 10);
            
            // Close button event
            const closeBtn = notification.querySelector('.notification-close');
            closeBtn.addEventListener('click', () => {
                notification.classList.remove('show');
                setTimeout(() => {
                    notification.remove();
                }, 300);
            });
            
            // Auto remove after duration
            if (duration > 0) {
                setTimeout(() => {
                    if (notification.parentNode) {
                        notification.classList.remove('show');
                        setTimeout(() => {
                            notification.remove();
                        }, 300);
                    }
                }, duration);
            }
            
            return notification;
        }
        
        function updateEmailPreview() {
            emailPreview.innerHTML = emailContent.value || 'Email preview will appear here...';
        }
        
        function showEmailPreview() {
            const subject = emailSubject.value;
            const content = emailContent.value;
            
            if (!subject || !content) {
                showNotification('error', 'Missing Information', 'Please fill in both subject and content before previewing.');
                return;
            }
            
            emailPreviewModalContent.innerHTML = `
                <h3>${subject}</h3>
                <div style="margin-top: 15px; white-space: pre-wrap;">${content}</div>
            `;
            
            emailPreviewModal.classList.add('active');
        }
        
        function hideEmailPreview() {
            emailPreviewModal.classList.remove('active');
        }
        
        function updateSelectedInvestorsTags() {
            selectedInvestorsTags.innerHTML = '';
            const selectedOptions = Array.from(investorSelect.selectedOptions);
            
            selectedOptions.forEach(option => {
                const tag = document.createElement('div');
                tag.className = 'recipient-tag';
                tag.innerHTML = `
                    ${option.textContent}
                    <span class="remove" data-value="${option.value}">&times;</span>
                `;
                selectedInvestorsTags.appendChild(tag);
            });
            
            // Add remove functionality
            selectedInvestorsTags.querySelectorAll('.remove').forEach(removeBtn => {
                removeBtn.addEventListener('click', function() {
                    const value = this.getAttribute('data-value');
                    const option = investorSelect.querySelector(`option[value="${value}"]`);
                    if (option) {
                        option.selected = false;
                    }
                    updateSelectedInvestorsTags();
                });
            });
        }
        
        function updateManualEmailsTags() {
            manualEmailsTags.innerHTML = '';
            const emails = manualEmails.value.split(/[\n,]/).map(email => email.trim()).filter(email => email);
            
            emails.forEach(email => {
                if (validator.isEmail(email)) {
                    const tag = document.createElement('div');
                    tag.className = 'recipient-tag';
                    tag.innerHTML = `
                        ${email}
                        <span class="remove" data-email="${email}">&times;</span>
                    `;
                    manualEmailsTags.appendChild(tag);
                }
            });
            
            // Add remove functionality
            manualEmailsTags.querySelectorAll('.remove').forEach(removeBtn => {
                removeBtn.addEventListener('click', function() {
                    const emailToRemove = this.getAttribute('data-email');
                    const emails = manualEmails.value.split(/[\n,]/).map(email => email.trim()).filter(email => email && email !== emailToRemove);
                    manualEmails.value = emails.join('\n');
                    updateManualEmailsTags();
                });
            });
        }
        
        function handleExcelUpload(event) {
            const file = event.target.files[0];
            if (!file) return;
            
            const reader = new FileReader();
            
            reader.onload = function(e) {
                try {
                    const data = new Uint8Array(e.target.result);
                    const workbook = XLSX.read(data, { type: 'array' });
                    
                    // Get first worksheet
                    const worksheet = workbook.Sheets[workbook.SheetNames[0]];
                    const jsonData = XLSX.utils.sheet_to_json(worksheet);
                    
                    // Extract emails from Excel data
                    excelEmails = [];
                    jsonData.forEach(row => {
                        // Look for email in any column
                        for (let key in row) {
                            if (validator.isEmail(String(row[key]))) {
                                excelEmails.push(String(row[key]));
                                break;
                            }
                        }
                    });
                    
                    if (excelEmails.length === 0) {
                        showNotification('error', 'No Emails Found', 'No valid email addresses found in the Excel file.');
                        return;
                    }
                    
                    // Show uploaded file info
                    const uploadedFiles = document.getElementById('uploaded-files');
                    uploadedFiles.innerHTML = `
                        <div class="uploaded-file">
                            <div class="file-info">
                                <i class="fas fa-file-excel"></i>
                                <div>
                                    <div class="file-name">${file.name}</div>
                                    <div class="file-size">${(file.size / 1024).toFixed(2)} KB</div>
                                </div>
                            </div>
                            <button class="file-remove" onclick="clearExcelUpload()">
                                <i class="fas fa-times"></i>
                            </button>
                        </div>
                    `;
                    
                    // Show email preview
                    excelPreview.style.display = 'block';
                    excelEmailsPreview.innerHTML = '';
                    
                    excelEmails.slice(0, 10).forEach(email => {
                        const tag = document.createElement('div');
                        tag.className = 'recipient-tag';
                        tag.textContent = email;
                        excelEmailsPreview.appendChild(tag);
                    });
                    
                    if (excelEmails.length > 10) {
                        const moreTag = document.createElement('div');
                        moreTag.className = 'recipient-tag';
                        moreTag.textContent = `+${excelEmails.length - 10} more`;
                        excelEmailsPreview.appendChild(moreTag);
                    }
                    
                    showNotification('success', 'Excel Uploaded', `Found ${excelEmails.length} email addresses in the file.`);
                    
                } catch (error) {
                    console.error('Error reading Excel file:', error);
                    showNotification('error', 'Upload Failed', 'Failed to read the Excel file. Please make sure it is a valid Excel file.');
                }
            };
            
            reader.onerror = function() {
                showNotification('error', 'Upload Failed', 'Failed to read the file.');
            };
            
            reader.readAsArrayBuffer(file);
        }
        
        function clearExcelUpload() {
            excelFile.value = '';
            document.getElementById('uploaded-files').innerHTML = '';
            excelPreview.style.display = 'none';
            excelEmails = [];
        }
        
        function showLoadTemplateModal() {
            templateModalTitle.textContent = 'Load Template';
            modalTemplateName.value = '';
            modalTemplateSubject.value = '';
            modalTemplateContent.value = '';
            
            // Populate template select
            const templateSelect = document.createElement('select');
            templateSelect.id = 'template-select';
            templateSelect.className = 'form-control';
            templateSelect.innerHTML = '<option value="">-- Select Template --</option>';
            
            templates.forEach(template => {
                const option = document.createElement('option');
                option.value = template._id;
                option.textContent = template.name;
                templateSelect.appendChild(option);
            });
            
            // Replace content area with template select
            const contentArea = modalTemplateContent.parentNode;
            const label = contentArea.querySelector('label');
            contentArea.innerHTML = '';
            contentArea.appendChild(label);
            contentArea.appendChild(templateSelect);
            
            // Add event listener for template selection
            templateSelect.addEventListener('change', function() {
                const selectedTemplate = templates.find(t => t._id === this.value);
                if (selectedTemplate) {
                    modalTemplateName.value = selectedTemplate.name;
                    modalTemplateSubject.value = selectedTemplate.subject;
                    modalTemplateContent.value = selectedTemplate.content;
                }
            });
            
            templateModal.classList.add('active');
        }
        
        function hideTemplateModal() {
            templateModal.classList.remove('active');
            
            // Reset template modal content
            const contentArea = modalTemplateContent.parentNode;
            contentArea.innerHTML = `
                <label for="modal-template-content">Content</label>
                <textarea id="modal-template-content" class="form-control" rows="10" placeholder="Enter template content"></textarea>
            `;
            modalTemplateContent = document.getElementById('modal-template-content');
        }
        
        // API Functions
        async function handleLogin(e) {
            e.preventDefault();
            
            const username = document.getElementById('username').value;
            const password = document.getElementById('password').value;
            
            try {
                showNotification('info', 'Authenticating', 'Please wait while we verify your credentials...', 0);
                
                const response = await fetch(`https://hashvex-technologies-backend.onrender.com/admin/login`, {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json',
                    },
                    body: JSON.stringify({ username, password })
                });
                
                if (response.ok) {
                    const data = await response.json();
                    authToken = data.token;
                    currentUser = data.user;
                    
                    // Update UI with user info
                    if (currentUser) {
                        userName.textContent = currentUser.name;
                        userAvatar.textContent = currentUser.name.charAt(0).toUpperCase();
                        headerActions.style.display = 'flex';
                    }
                    
                    // Hide login modal and show dashboard
                    loginModal.style.display = 'none';
                    adminDashboard.style.display = 'block';
                    
                    // Show success notification
                    showNotification('success', 'Login Successful', `Welcome back, ${currentUser?.name || 'Admin'}!`);
                    
                    // Fetch initial data
                    fetchDashboardStats();
                    fetchAllInvestors();
                } else {
                    const errorData = await response.json();
                    showNotification('error', 'Login Failed', errorData.message || 'Please check your credentials.');
                }
            } catch (error) {
                console.error('Login error:', error);
                showNotification('error', 'Connection Error', 'An error occurred during login. Please try again.');
            }
        }
        
        async function fetchDashboardStats() {
            try {
                const response = await fetch(`${API_BASE_URL}/admin/stats`, {
                    headers: {
                        'Authorization': `Bearer ${authToken}`
                    }
                });
                
                if (response.ok) {
                    const data = await response.json();
                    
                    // Update stats
                    document.getElementById('total-investors').textContent = data.data.totalInvestors || 0;
                    document.getElementById('emails-sent').textContent = data.data.emailsSent || 0;
                    document.getElementById('open-rate').textContent = `${data.data.openRate || 0}%`;
                    document.getElementById('last-activity').textContent = data.data.lastActivity || '-';
                    
                    // Update trends
                    document.getElementById('investor-trend').textContent = `${data.data.investorTrend || 0}%`;
                    document.getElementById('email-trend').textContent = `${data.data.emailTrend || 0}%`;
                    document.getElementById('open-trend').textContent = `${data.data.openTrend || 0}%`;
                    document.getElementById('activity-time').textContent = data.data.activityTime || 'Just now';
                }
            } catch (error) {
                console.error('Error fetching stats:', error);
                showNotification('error', 'Data Error', 'Failed to load dashboard statistics.');
            }
        }
        
        async function fetchAllInvestors() {
            try {
                const response = await fetch(`${API_BASE_URL}/admin/investors/all`, {
                    headers: {
                        'Authorization': `Bearer ${authToken}`
                    }
                });
                
                if (response.ok) {
                    const data = await response.json();
                    investors = data.data || [];
                    
                    // Update investor select dropdown
                    investorSelect.innerHTML = '';
                    investors.forEach(investor => {
                        const option = document.createElement('option');
                        option.value = investor._id;
                        option.textContent = `${investor.name} (${investor.email})`;
                        investorSelect.appendChild(option);
                    });
                }
            } catch (error) {
                console.error('Error fetching all investors:', error);
                showNotification('error', 'Data Error', 'Failed to load investor data.');
            }
        }
        
        async function fetchInvestors() {
            try {
                const searchQuery = document.getElementById('investor-search').value;
                const filterValue = document.getElementById('investor-filter').value;
                
                let url = `${API_BASE_URL}/admin/investors?page=${currentInvestorPage}&limit=${itemsPerPage}`;
                if (searchQuery) url += `&search=${encodeURIComponent(searchQuery)}`;
                if (filterValue) url += `&filter=${encodeURIComponent(filterValue)}`;
                
                const response = await fetch(url, {
                    headers: {
                        'Authorization': `Bearer ${authToken}`
                    }
                });
                
                if (response.ok) {
                    const data = await response.json();
                    const investors = data.data.investors || [];
                    
                    // Update investor table
                    const investorTable = document.getElementById('investor-table');
                    investorTable.innerHTML = '';
                    
                    if (investors.length === 0) {
                        investorTable.innerHTML = `
                            <tr>
                                <td colspan="6" style="text-align: center; padding: 20px; color: var(--text-secondary)">
                                    No investors found
                                </td>
                            </tr>
                        `;
                        return;
                    }
                    
                    investors.forEach(investor => {
                        const row = document.createElement('tr');
                        row.innerHTML = `
                            <td>${investor.name}</td>
                            <td>${investor.email}</td>
                            <td>${new Date(investor.joinDate).toLocaleDateString()}</td>
                            <td>${investor.tier}</td>
                            <td><span class="status-badge">${investor.status}</span></td>
                            <td>$${investor.totalInvested}</td>
                        `;
                        investorTable.appendChild(row);
                    });
                    
                    // Render pagination
                    renderPagination('investor-pagination', currentInvestorPage, data.data.totalPages, 'investor');
                }
            } catch (error) {
                console.error('Error fetching investors:', error);
                showNotification('error', 'Data Error', 'Failed to load investor data.');
            }
        }
        
        async function fetchEmailHistory() {
            try {
                const searchQuery = document.getElementById('email-search').value;
                const filterValue = document.getElementById('email-filter').value;
                
                let url = `${API_BASE_URL}/admin/emails?page=${currentEmailPage}&limit=${itemsPerPage}`;
                if (searchQuery) url += `&search=${encodeURIComponent(searchQuery)}`;
                if (filterValue) url += `&filter=${encodeURIComponent(filterValue)}`;
                
                const response = await fetch(url, {
                    headers: {
                        'Authorization': `Bearer ${authToken}`
                    }
                });
                
                if (response.ok) {
                    const data = await response.json();
                    emailHistory = data.data.emails || [];
                    
                    // Update email history table
                    const emailHistoryTable = document.getElementById('email-history-table');
                    emailHistoryTable.innerHTML = '';
                    
                    if (emailHistory.length === 0) {
                        emailHistoryTable.innerHTML = `
                            <tr>
                                <td colspan="6" style="text-align: center; padding: 20px; color: var(--text-secondary)">
                                    No email history found
                                </td>
                            </tr>
                        `;
                        return;
                    }
                    
                    emailHistory.forEach(email => {
                        const row = document.createElement('tr');
                        row.innerHTML = `
                            <td>${email.subject}</td>
                            <td>${email.recipientCount}</td>
                            <td>${new Date(email.sentDate).toLocaleString()}</td>
                            <td>${email.openRate}%</td>
                            <td><span class="status-badge">${email.status}</span></td>
                            <td>${email.sentBy}</td>
                        `;
                        emailHistoryTable.appendChild(row);
                    });
                    
                    // Render pagination
                    renderPagination('email-pagination', currentEmailPage, data.data.totalPages, 'email');
                }
            } catch (error) {
                console.error('Error fetching email history:', error);
                showNotification('error', 'Data Error', 'Failed to load email history.');
            }
        }
        
        async function fetchTemplates() {
            try {
                const searchQuery = document.getElementById('template-search').value;
                
                let url = `${API_BASE_URL}/admin/templates?page=${currentTemplatePage}&limit=${itemsPerPage}`;
                if (searchQuery) url += `&search=${encodeURIComponent(searchQuery)}`;
                
                const response = await fetch(url, {
                    headers: {
                        'Authorization': `Bearer ${authToken}`
                    }
                });
                
                if (response.ok) {
                    const data = await response.json();
                    templates = data.data.templates || [];
                    
                    // Update template table
                    const templateTable = document.getElementById('template-table');
                    templateTable.innerHTML = '';
                    
                    if (templates.length === 0) {
                        templateTable.innerHTML = `
                            <tr>
                                <td colspan="6" style="text-align: center; padding: 20px; color: var(--text-secondary)">
                                    No templates found
                                </td>
                            </tr>
                        `;
                        return;
                    }
                    
                    templates.forEach(template => {
                        const row = document.createElement('tr');
                        row.innerHTML = `
                            <td>${template.name}</td>
                            <td>${template.subject}</td>
                            <td>${template.category}</td>
                            <td>${new Date(template.updatedAt).toLocaleDateString()}</td>
                            <td>${template.usedCount || 0}</td>
                            <td>
                                <button class="btn btn-secondary" onclick="loadTemplateIntoEditor('${template._id}')">
                                    <i class="fas fa-edit"></i> Load
                                </button>
                                <button class="btn btn-danger" onclick="deleteTemplate('${template._id}')">
                                    <i class="fas fa-trash"></i> Delete
                                </button>
                            </td>
                        `;
                        templateTable.appendChild(row);
                    });
                    
                    // Render pagination
                    renderPagination('template-pagination', currentTemplatePage, data.data.totalPages, 'template');
                }
            } catch (error) {
                console.error('Error fetching templates:', error);
                showNotification('error', 'Data Error', 'Failed to load email templates.');
            }
        }
        
        async function fetchAnalytics() {
            try {
                const period = document.getElementById('analytics-period').value;
                
                const response = await fetch(`${API_BASE_URL}/admin/analytics?period=${period}`, {
                    headers: {
                        'Authorization': `Bearer ${authToken}`
                    }
                });
                
                if (response.ok) {
                    const data = await response.json();
                    analyticsData = data.data;
                    
                    // Update analytics stats
                    document.getElementById('delivery-rate').textContent = `${analyticsData.deliveryRate || 0}%`;
                    document.getElementById('analytics-open-rate').textContent = `${analyticsData.openRate || 0}%`;
                    
                    // Update trends
                    document.getElementById('delivery-trend').textContent = `${analyticsData.deliveryTrend || 0}%`;
                    document.getElementById('analytics-open-trend').textContent = `${analyticsData.openTrend || 0}%`;
                }
            } catch (error) {
                console.error('Error fetching analytics:', error);
                showNotification('error', 'Data Error', 'Failed to load analytics data.');
            }
        }
        
        function renderPagination(containerId, currentPage, totalPages, type) {
            const container = document.getElementById(containerId);
            container.innerHTML = '';
            
            if (totalPages <= 1) return;
            
            // Previous button
            const prevBtn = document.createElement('div');
            prevBtn.className = 'page-btn';
            prevBtn.innerHTML = '<i class="fas fa-chevron-left"></i>';
            if (currentPage > 1) {
                prevBtn.addEventListener('click', () => {
                    if (type === 'investor') {
                        currentInvestorPage--;
                        fetchInvestors();
                    } else if (type === 'email') {
                        currentEmailPage--;
                        fetchEmailHistory();
                    } else if (type === 'template') {
                        currentTemplatePage--;
                        fetchTemplates();
                    }
                });
            } else {
                prevBtn.style.opacity = '0.5';
                prevBtn.style.cursor = 'not-allowed';
            }
            container.appendChild(prevBtn);
            
            // Page numbers
            const startPage = Math.max(1, currentPage - 2);
            const endPage = Math.min(totalPages, currentPage + 2);
            
            for (let i = startPage; i <= endPage; i++) {
                const pageBtn = document.createElement('div');
                pageBtn.className = `page-btn ${i === currentPage ? 'active' : ''}`;
                pageBtn.textContent = i;
                pageBtn.addEventListener('click', () => {
                    if (i !== currentPage) {
                        if (type === 'investor') {
                            currentInvestorPage = i;
                            fetchInvestors();
                        } else if (type === 'email') {
                            currentEmailPage = i;
                            fetchEmailHistory();
                        } else if (type === 'template') {
                            currentTemplatePage = i;
                            fetchTemplates();
                        }
                    }
                });
                container.appendChild(pageBtn);
            }
            
            // Next button
            const nextBtn = document.createElement('div');
            nextBtn.className = 'page-btn';
            nextBtn.innerHTML = '<i class="fas fa-chevron-right"></i>';
            if (currentPage < totalPages) {
                nextBtn.addEventListener('click', () => {
                    if (type === 'investor') {
                        currentInvestorPage++;
                        fetchInvestors();
                    } else if (type === 'email') {
                        currentEmailPage++;
                        fetchEmailHistory();
                    } else if (type === 'template') {
                        currentTemplatePage++;
                        fetchTemplates();
                    }
                });
            } else {
                nextBtn.style.opacity = '0.5';
                nextBtn.style.cursor = 'not-allowed';
            }
            container.appendChild(nextBtn);
        }
        
        async function sendEmail() {
            const recipientTypeValue = recipientType.value;
            const subject = emailSubject.value;
            const content = emailContent.value;
            const enableTracking = trackingEnabled.checked;
            const scheduleEmail = scheduleEnabled.checked;
            const scheduleDate = document.getElementById('schedule-date').value;
            const saveAsTemplate = saveTemplate.checked;
            const templateNameValue = templateName.value;
            
            if (!subject || !content) {
                showNotification('error', 'Missing Information', 'Please fill in both subject and content.');
                return;
            }
            
            if (saveAsTemplate && !templateNameValue) {
                showNotification('error', 'Missing Information', 'Please enter a template name.');
                return;
            }
            
            let recipients = [];
            
            if (recipientTypeValue === 'all') {
                // Send to all investors - empty array indicates all
                recipients = [];
            } else if (recipientTypeValue === 'selected') {
                // Get selected investor IDs
                const selectedOptions = Array.from(investorSelect.selectedOptions);
                recipients = selectedOptions.map(option => option.value);
            } else if (recipientTypeValue === 'manual') {
                // Get manually entered emails
                const emails = manualEmails.value.split(/[\n,]/).map(email => email.trim()).filter(email => email);
                recipients = emails;
            } else if (recipientTypeValue === 'excel') {
                // Use emails from Excel file
                if (excelEmails.length === 0) {
                    showNotification('error', 'No Emails', 'Please upload an Excel file with email addresses first.');
                    return;
                }
                recipients = excelEmails;
            }
            
            try {
                showNotification('info', 'Sending Email', 'Please wait while we send your email...', 0);
                
                let endpoint = '/admin/send-email';
                let emailData = {
                    recipients,
                    subject,
                    content,
                    enableTracking,
                    scheduleEmail,
                    scheduleDate: scheduleEmail ? scheduleDate : null,
                    saveAsTemplate,
                    templateName: saveAsTemplate ? templateNameValue : null
                };
                
                // If sending from Excel, use the bulk endpoint
                if (recipientTypeValue === 'excel') {
                    endpoint = '/admin/send-bulk-email';
                    emailData = {
                        excelData: excelEmails.map(email => ({ email })),
                        subject,
                        content,
                        enableTracking
                    };
                }
                
                const response = await fetch(`${API_BASE_URL}${endpoint}`, {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json',
                        'Authorization': `Bearer ${authToken}`
                    },
                    body: JSON.stringify(emailData)
                });
                
                if (response.ok) {
                    showNotification('success', 'Email Sent', 'Your email has been sent successfully!');
                    
                    // Reset form
                    emailSubject.value = '';
                    emailContent.value = '';
                    updateEmailPreview();
                    
                    // Refresh data
                    fetchDashboardStats();
                    fetchEmailHistory();
                    
                    if (saveAsTemplate) {
                        fetchTemplates();
                    }
                } else {
                    const errorData = await response.json();
                    showNotification('error', 'Send Failed', errorData.message || 'Failed to send email. Please try again.');
                }
            } catch (error) {
                console.error('Error sending email:', error);
                showNotification('error', 'Connection Error', 'An error occurred while sending the email. Please try again.');
            }
        }
        
        async function sendEmailFromPreview() {
            hideEmailPreview();
            sendEmail();
        }
        
        async function saveTemplateHandler() {
            const name = modalTemplateName.value;
            const subject = modalTemplateSubject.value;
            const content = modalTemplateContent.value;
            
            if (!name || !subject || !content) {
                showNotification('error', 'Missing Information', 'Please fill in all template fields.');
                return;
            }
            
            try {
                showNotification('info', 'Saving Template', 'Please wait while we save your template...', 0);
                
                const templateData = {
                    name,
                    subject,
                    content
                };
                
                const response = await fetch(`${API_BASE_URL}/admin/templates`, {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json',
                        'Authorization': `Bearer ${authToken}`
                    },
                    body: JSON.stringify(templateData)
                });
                
                if (response.ok) {
                    showNotification('success', 'Template Saved', 'Your template has been saved successfully!');
                    hideTemplateModal();
                    fetchTemplates();
                } else {
                    const errorData = await response.json();
                    showNotification('error', 'Save Failed', errorData.message || 'Failed to save template. Please try again.');
                }
            } catch (error) {
                console.error('Error saving template:', error);
                showNotification('error', 'Connection Error', 'An error occurred while saving the template. Please try again.');
            }
        }
        
        async function loadTemplateIntoEditor(templateId) {
            try {
                const response = await fetch(`${API_BASE_URL}/admin/templates/${templateId}`, {
                    headers: {
                        'Authorization': `Bearer ${authToken}`
                    }
                });
                
                if (response.ok) {
                    const data = await response.json();
                    const template = data.data.template;
                    
                    emailSubject.value = template.subject;
                    emailContent.value = template.content;
                    updateEmailPreview();
                    
                    showNotification('success', 'Template Loaded', `Template "${template.name}" has been loaded.`);
                } else {
                    throw new Error('Failed to load template');
                }
            } catch (error) {
                console.error('Error loading template:', error);
                showNotification('error', 'Load Failed', 'Failed to load template. Please try again.');
            }
        }
        
        async function deleteTemplate(templateId) {
            if (!confirm('Are you sure you want to delete this template?')) {
                return;
            }
            
            try {
                showNotification('info', 'Deleting Template', 'Please wait while we delete your template...', 0);
                
                const response = await fetch(`${API_BASE_URL}/admin/templates/${templateId}`, {
                    method: 'DELETE',
                    headers: {
                        'Authorization': `Bearer ${authToken}`
                    }
                });
                
                if (response.ok) {
                    showNotification('success', 'Template Deleted', 'Your template has been deleted successfully!');
                    fetchTemplates();
                } else {
                    const errorData = await response.json();
                    showNotification('error', 'Delete Failed', errorData.message || 'Failed to delete template. Please try again.');
                }
            } catch (error) {
                console.error('Error deleting template:', error);
                showNotification('error', 'Connection Error', 'An error occurred while deleting the template. Please try again.');
            }
        }
        
        // Email validation
        const validator = {
            isEmail: function(email) {
                const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
                return emailRegex.test(email);
            }
        };
        
        // Excel library (simple implementation)
        const XLSX = {
            read: function(data, options) {
                // This is a simplified implementation
                // In a real application, you would use a proper Excel parsing library
                return {
                    SheetNames: ['Sheet1'],
                    Sheets: {
                        'Sheet1': {}
                    }
                };
            },
            utils: {
                sheet_to_json: function() {
                    return [];
                }
            }
        };
    </script>
</body>
</html>
