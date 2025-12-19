import pool from "../DB/db.js";

/**
 * Create a new user (manual registration)
 */
export const createUser = async (name, email, hashedPassword, role, verificationToken, provider, uid) => {
  try {
    // Validate role as a string and ensure it's an allowed value
    const validRoles = ["student", "instructor", "admin", "super_admin"];
    if (Array.isArray(role)) {
      console.error(`❌ Role parameter is an array: ${JSON.stringify(role)}. Expected a string.`);
      throw new Error("Role must be a string, not an array.");
    }
    if (typeof role !== "string" || !validRoles.includes(role)) {
      console.error(`❌ Invalid role: ${role}. Expected one of ${validRoles.join(", ")}.`);
      throw new Error(`Invalid role: ${role}. Must be one of ${validRoles.join(", ")}.`);
    }
    const userRole = role;

    const query = `
      INSERT INTO users (name, email, password, role, verified, verification_token, provider, uid, created_at, updated_at)
      VALUES ($1, $2, $3, $4, $5, $6, $7, $8, NOW(), NOW())
      RETURNING id, name, email, role, verified, provider, uid, created_at
    `;

    const values = [name, email, hashedPassword, userRole, false, verificationToken, provider, uid];
    const result = await pool.query(query, values);

    return result.rows[0];
  } catch (error) {
    if (error.code === "23505") {
      console.warn(`⚠️ Duplicate email: ${email}`);
      throw new Error("User with this email already exists");
    }
    console.error("❌ Error creating user:", error.message, error.stack);
    throw error;
  }
};

/**
 * Create a Google user
 */
export const createGoogleUser = async (name, email, uid, role) => {
  try {
    // Validate role as a string
    const validRoles = ["student", "instructor", "admin", "super_admin"];
    if (Array.isArray(role)) {
      console.error(`❌ Role parameter is an array: ${JSON.stringify(role)}. Expected a string.`);
      throw new Error("Role must be a string, not an array.");
    }
    if (typeof role !== "string" || !validRoles.includes(role)) {
      console.error(`❌ Invalid role: ${role}. Expected one of ${validRoles.join(", ")}.`);
      throw new Error(`Invalid role: ${role}. Must be one of ${validRoles.join(", ")}.`);
    }
    const userRole = role;


    const query = `
      INSERT INTO users (name, email, role, verified, provider, uid, created_at, updated_at)
      VALUES ($1, $2, $3, $4, $5, $6, NOW(), NOW())
      RETURNING id, name, email, role, verified, provider, uid, created_at
    `;

    const values = [name, email, userRole, true, "google", uid];
    const result = await pool.query(query, values);

    return result.rows[0];
  } catch (error) {
    if (error.code === "23505") {
      console.warn(`⚠️ Duplicate email: ${email}`);
      throw new Error("User with this email already exists");
    }
    console.error("❌ Error creating Google user:", error.message, error.stack);
    throw error;
  }
};

/**
 * Find user by email
 */
export const findUserByEmail = async (email) => {
  try {
    const query = "SELECT * FROM users WHERE email = $1";
    const result = await pool.query(query, [email]);
    return result.rows[0] || null;
  } catch (error) {
    console.error("❌ Error finding user by email:", error.message);
    throw new Error("Database error during user lookup");
  }
};

/**
 * Get user by email (alias for findUserByEmail)
 */
export const getUserByEmail = async (email) => {
  try {
    const query = "SELECT * FROM users WHERE email = $1";
    const result = await pool.query(query, [email]);
    return result.rows[0] || null;
  } catch (error) {
    console.error("❌ Error getting user by email:", error.message);
    throw new Error("Database error during user lookup");
  }
};

/**
 * Find user by UID
 */
export const findUserByUID = async (uid) => {
  try {
    const query = "SELECT * FROM users WHERE uid = $1";
    const result = await pool.query(query, [uid]);
    return result.rows[0] || null;
  } catch (error) {
    console.error("❌ Error finding user by UID:", error.message);
    throw new Error("Database error during UID lookup");
  }
};

/**
 * Find user by verification token
 */
export const findUserByVerificationToken = async (token) => {
  try {
    const query = "SELECT * FROM users WHERE verification_token = $1";
    const result = await pool.query(query, [token]);
    return result.rows[0] || null;
  } catch (error) {
    console.error("❌ Error finding user by verification token:", error.message);
    throw new Error("Database error during verification token lookup");
  }
};

/**
 * Find user by reset token (renamed to support resetId)
 */
export const findUserByResetToken = async (resetId) => {
  try {
    const query = "SELECT * FROM users WHERE reset_token = $1 AND reset_token_expires > NOW()";
    const result = await pool.query(query, [resetId]);
    return result.rows[0] || null;
  } catch (error) {
    console.error("❌ Error finding user by reset token:", error.message);
    throw new Error("Database error during reset token lookup");
  }
};

/**
 * Verify user by token
 */
export const verifyUser = async (token) => {
  try {
    const query = `
      UPDATE users 
      SET verified = true, verification_token = NULL, updated_at = NOW() 
      WHERE verification_token = $1 
      RETURNING id, name, email, role, verified
    `;
    const result = await pool.query(query, [token]);
    return result.rows[0] || null;
  } catch (error) {
    console.error("❌ Error verifying user:", error.message);
    throw new Error("Database error during user verification");
  }
};

/**
 * Update reset token (supports resetId and expiration)
 */
export const updateResetToken = async (email, resetId, expiresAt) => {
  try {
    const query = `
      UPDATE users 
      SET reset_token = $1, reset_token_expires = $2, updated_at = NOW() 
      WHERE email = $3 
      RETURNING id, name, email
    `;
    const result = await pool.query(query, [resetId, expiresAt, email]);
    return result.rows[0] || null;
  } catch (error) {
    console.error("❌ Error updating reset token:", error.message);
    throw new Error("Database error during reset token update");
  }
};

/**
 * Update password by user ID (for both logged-in and reset flows)
 */
export const updatePasswordById = async (userId, hashedPassword) => {
  try {
    const query = `
      UPDATE users 
      SET password = $1, updated_at = NOW() 
      WHERE id = $2 
      RETURNING id, name, email, role
    `;
    const result = await pool.query(query, [hashedPassword, userId]);
    return result.rows[0] || null;
  } catch (error) {
    console.error("❌ Error updating password by ID:", error.message);
    throw new Error("Database error during password update");
  }
};

/**
 * Get all users (admin only)
 */
export const getAllUsers = async (requestingUserRole) => {
  try {
    if (!["admin", "super_admin"].includes(requestingUserRole)) {
      console.warn(`⚠️ Insufficient permissions: ${requestingUserRole}`);
      throw new Error("Insufficient permissions to view all users");
    }

    const query = `
      SELECT id, name, email, role, verified, created_at 
      FROM users 
      ORDER BY created_at DESC
    `;
    const result = await pool.query(query);
    return result.rows;
  } catch (error) {
    console.error("❌ Error getting all users:", error.message);
    throw error;
  }
};

/**
 * Update user role (admin only)
 */
export const updateUserRole = async (userId, newRole, requestingUserRole) => {
  try {
    if (requestingUserRole !== "super_admin" && requestingUserRole !== "admin") {
      console.warn(`⚠️ Insufficient permissions: ${requestingUserRole}`);
      throw new Error("Insufficient permissions to change user roles");
    }

    if (requestingUserRole === "admin" && ["admin", "super_admin"].includes(newRole)) {
      console.warn(`⚠️ Admin cannot promote to ${newRole}`);
      throw new Error("Admin users cannot promote users to admin or super admin roles");
    }

    // Validate newRole
    const validRoles = ["student", "instructor", "admin", "super_admin"];
    if (Array.isArray(newRole)) {
      console.error(`❌ New role is an array: ${JSON.stringify(newRole)}. Expected a string.`);
      throw new Error("New role must be a string, not an array.");
    }
    if (!validRoles.includes(newRole)) {
      console.error(`❌ Invalid new role: ${newRole}. Expected one of ${validRoles.join(", ")}.`);
      throw new Error(`Invalid new role: ${newRole}. Must be one of ${validRoles.join(", ")}.`);
    }
    const userRole = newRole;

    const query = `
      UPDATE users 
      SET role = $1, updated_at = NOW() 
      WHERE id = $2 
      RETURNING id, name, email, role, verified
    `;
    const result = await pool.query(query, [userRole, userId]);
    return result.rows[0] || null;
  } catch (error) {
    console.error("❌ Error updating user role:", error.message);
    throw error;
  }
};

/**
 * Delete user (super admin only)
 */
export const deleteUser = async (userId, requestingUserRole) => {
  try {
    if (requestingUserRole !== "super_admin") {
      console.warn(`⚠️ Insufficient permissions: ${requestingUserRole}`);
      throw new Error("Only super admins can delete users");
    }

    const query = "DELETE FROM users WHERE id = $1 RETURNING id, name, email";
    const result = await pool.query(query, [userId]);
    return result.rows[0] || null;
  } catch (error) {
    console.error("❌ Error deleting user:", error.message);
    throw error;
  }
};

/**
 * Get recently verified users
 */
export const getRecentlyVerifiedUsers = async () => {
  try {
    const query = `
      SELECT id, name, email, role, verified, created_at 
      FROM users 
      WHERE verified = true AND verification_token IS NULL
      AND updated_at > NOW() - INTERVAL '1 hour'
      ORDER BY updated_at DESC
      LIMIT 5
    `;
    const result = await pool.query(query);
    return result.rows;
  } catch (error) {
    console.error("❌ Error getting recently verified users:", error.message);
    throw error;
  }
};

/**
 * Find user by ID
 */
export const getUserById = async (id) => {
  try {
    const query = "SELECT id, name, email, role, verified, provider, uid, created_at FROM users WHERE id = $1";
    const result = await pool.query(query, [id]);
    return result.rows[0] || null;
  } catch (error) {
    console.error("❌ Error getting user by ID:", error.message);
    throw error;
  }
};

/**
 * Get users by role
 */
export const getUsersByRole = async (role) => {
  try {
    if (Array.isArray(role)) {
      console.error(`❌ Role parameter is an array: ${JSON.stringify(role)}. Expected a string.`);
      throw new Error("Role must be a string, not an array.");
    }
    const validRoles = ["student", "instructor", "admin", "super_admin"];
    if (!validRoles.includes(role)) {
      console.error(`❌ Invalid role: ${role}. Expected one of ${validRoles.join(", ")}.`);
      throw new Error(`Invalid role: ${role}. Must be one of ${validRoles.join(", ")}.`);
    }
    const query = `
      SELECT id, name, email, role, verified, created_at 
      FROM users 
      WHERE role = $1 
      ORDER BY name ASC
    `;
    const result = await pool.query(query, [role]);
    return result.rows;
  } catch (error) {
    console.error("❌ Error getting users by role:", error.message);
    throw error;
  }
};

/**
 * Search users by name or email
 */
export const searchUsers = async (searchTerm) => {
  try {
    const query = `
      SELECT id, name, email, role, verified, created_at 
      FROM users 
      WHERE name ILIKE $1 OR email ILIKE $1 
      ORDER BY name ASC
    `;
    const result = await pool.query(query, [`%${searchTerm}%`]);
    return result.rows;
  } catch (error) {
    console.error("❌ Error searching users:", error.message);
    throw error;
  }
};

/**
 * Check if user exists by email
 */
export const userExistsByEmail = async (email) => {
  try {
    const query = "SELECT id FROM users WHERE email = $1";
    const result = await pool.query(query, [email]);
    return result.rows.length > 0;
  } catch (error) {
    console.error("❌ Error checking user existence:", error.message);
    throw error;
  }
};

/**
 * Get user stats (admin dashboard)
 */
export const getUserStats = async () => {
  try {
    const query = `
      SELECT 
        COUNT(*) as total_users,
        COUNT(CASE WHEN role = 'student' THEN 1 END) as total_students,
        COUNT(CASE WHEN role = 'instructor' THEN 1 END) as total_instructors,
        COUNT(CASE WHEN role = 'admin' THEN 1 END) as total_admins,
        COUNT(CASE WHEN verified = true THEN 1 END) as verified_users,
        COUNT(CASE WHEN verified = false THEN 1 END) as unverified_users
      FROM users
    `;
    const result = await pool.query(query);
    return result.rows[0];
  } catch (error) {
    console.error("❌ Error getting user stats:", error.message);
    throw error;
  }
};