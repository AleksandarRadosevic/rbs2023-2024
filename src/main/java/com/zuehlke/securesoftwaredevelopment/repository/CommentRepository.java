package com.zuehlke.securesoftwaredevelopment.repository;

import com.zuehlke.securesoftwaredevelopment.domain.Comment;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Repository;

import javax.sql.DataSource;
import java.sql.*;
import java.util.ArrayList;
import java.util.List;

@Repository
public class CommentRepository {

    private static final Logger LOG = LoggerFactory.getLogger(CommentRepository.class);


    private DataSource dataSource;

    public CommentRepository(DataSource dataSource) {
        this.dataSource = dataSource;
    }

    public void create(Comment comment) {
        String query = "insert into comments(giftId, userId, comment) values (?,?,?)";

        try (Connection connection = dataSource.getConnection();
             PreparedStatement statement = connection.prepareStatement(query);
        ) {
            statement.setInt(1, comment.getGiftId());
            statement.setInt(2, comment.getUserId());
            statement.setString(3, comment.getComment());
            statement.executeUpdate();
        } catch (SQLException e) {
            LOG.warn("Failed to create a comment for user {} and gift {}, Reason:{}", comment.getUserId(), comment.getGiftId(), e.toString());
        }
    }

    public List<Comment> getAll(String giftId) {
        List<Comment> commentList = new ArrayList<>();
        String query = "SELECT giftId, userId, comment FROM comments WHERE giftId = " + giftId;
        try (Connection connection = dataSource.getConnection();
             Statement statement = connection.createStatement();
             ResultSet rs = statement.executeQuery(query)) {
            while (rs.next()) {
                commentList.add(new Comment(rs.getInt(1), rs.getInt(2), rs.getString(3)));
            }
        } catch (SQLException e) {
            LOG.warn("Failed to get comments for gift {}, Reason:{}", giftId, e.toString());
            LOG.warn("Failed to retrieve comments for gift {}", giftId, e);
        }
        return commentList;
    }
}
